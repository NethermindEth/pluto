//! Compound libp2p node for the DKG ceremony.
//!
//! [`setup_node`] assembles all required sub-behaviours (relay, bcast, sync,
//! parsigex, peerinfo, frost-p2p), starts the swarm event loop in a background
//! task, and returns the user-facing handles needed by [`crate::dkg::run`].

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, relay,
    multiaddr::Protocol,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use pluto_cluster::definition::{Definition, NodeIdx};
use pluto_core::version::VERSION;
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    bootnode,
    gater::{self, ConnGater},
    k1::load_priv_key,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::{peer_id_from_key, verify_p2p_key},
    relay::{MutableRelayReservation, RelayRouter},
};
use pluto_parsigex::{Behaviour as ParsexBehaviour, Config as ParsexConfig};
use pluto_peerinfo::{
    Behaviour as PeerinfoBehaviour,
    config::{Config as PeerinfoConfig, LocalPeerInfo},
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    bcast::{self, Component as BcastComponent},
    dkg::Config,
    frostp2p::{FrostP2PBehaviour, FrostP2PHandle},
    sync::{self, Client as SyncClient, Server as SyncServer},
};

/// All handles returned from [`setup_node`] for use in the DKG flow.
pub struct NodeHandles {
    /// Node index in the cluster (peer index + share index).
    pub node_idx: NodeIdx,
    /// Bcast component for FROST cast rounds and node-sig exchange.
    pub bcast_comp: BcastComponent,
    /// Sync server – tracks step progress across all peers.
    pub sync_server: SyncServer,
    /// Sync clients – one per remote peer.
    pub sync_clients: Vec<SyncClient>,
    /// Parsigex handle for the Exchanger.
    pub parsigex_handle: pluto_parsigex::Handle,
    /// Handle for frost round-1 direct P2P messages.
    pub frost_p2p: FrostP2PHandle,
    /// Background swarm task; join to propagate panics.
    pub swarm_task: JoinHandle<()>,
}

/// Error from [`setup_node`].
#[derive(Debug, thiserror::Error)]
pub enum NodeSetupError {
    /// Failed to load the p2p private key from disk.
    #[error("failed to load p2p private key: {0}")]
    LoadKey(#[from] pluto_p2p::k1::K1Error),
    /// P2P key does not match any peer in the definition.
    #[error("p2p key verification failed: {0}")]
    VerifyKey(#[from] pluto_p2p::peer::PeerError),
    /// Relay resolution failed.
    #[error("failed to resolve relays: {0}")]
    Relays(#[from] pluto_p2p::bootnode::BootnodeError),
    /// libp2p node construction failed.
    #[error("failed to build DKG node: {0}")]
    Node(#[from] pluto_p2p::p2p::P2PError),
    /// Sync behaviour setup failed.
    #[error("sync setup failed: {0}")]
    Sync(#[from] crate::sync::Error),
    /// Node's peer ID is not in the cluster definition.
    #[error("this node's peer ID is not in the definition: {0}")]
    NodeIdx(#[from] pluto_cluster::definition::DefinitionError),
    /// Local peer ID was not set in the P2P context.
    #[error("local peer id unavailable")]
    LocalPeerId,
}

// ── Compound behaviour ──────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct DkgBehaviour {
    relay: relay::client::Behaviour,
    relay_reservation: MutableRelayReservation,
    relay_router: RelayRouter,
    bcast: bcast::Behaviour,
    sync: sync::Behaviour,
    parsigex: ParsexBehaviour,
    peerinfo: PeerinfoBehaviour,
    frost_p2p: FrostP2PBehaviour,
}

// ── setup_node ──────────────────────────────────────────────────────────────

/// Builds the DKG libp2p node, wires all sub-behaviours, and returns handles.
///
/// The caller is responsible for spawning client `run()` tasks and starting the
/// sync server after all handles are set up, which is done inside
/// [`crate::dkg::run`].
pub async fn setup_node(
    conf: &Config,
    definition: &Definition,
    ct: CancellationToken,
) -> Result<NodeHandles, NodeSetupError> {
    let key = load_priv_key(&conf.data_dir)?;
    let local_peer_id = peer_id_from_key(key.public_key())?;

    let peers = definition.peers()?;
    verify_p2p_key(&peers, &key)?;

    let peer_ids: Vec<PeerId> = definition.peer_ids()?;

    let def_hash = definition.definition_hash.clone();
    let def_hash_hex = hex::encode(&def_hash);

    let relay_strs: Vec<String> = conf.p2p.relays.iter().map(multiaddr_to_relay_str).collect();
    let relays = bootnode::new_relays(ct.child_token(), &relay_strs, &def_hash_hex).await?;

    let known_peers = peer_ids.clone();
    let conn_gater = ConnGater::new(
        gater::Config::closed()
            .with_relays(relays.clone())
            .with_peer_ids(known_peers.clone()),
    );

    let p2p_context = P2PContext::new(known_peers.clone());
    p2p_context.set_local_peer_id(local_peer_id);

    // Closures capture Option<T> that get filled during Node::new.
    let mut bcast_comp_out = None;
    let mut sync_server_out = None;
    let mut sync_clients_out = None;
    let mut parsigex_handle_out = None;
    let mut frost_p2p_handle_out = None;

    let node: Node<DkgBehaviour> = Node::new(
        conf.p2p.clone(),
        key.clone(),
        NodeType::TCP,
        false,
        p2p_context.clone(),
        |builder, _keypair, relay_client| {
            let p2p_ctx = builder.p2p_context();
            let local_id = p2p_ctx.local_peer_id().expect("local peer id set");

            // ── bcast ──────────────────────────────────────────────────────
            let (bcast_beh, bcast_comp) =
                bcast::Behaviour::new(peer_ids.clone(), p2p_ctx.clone(), key.clone());
            bcast_comp_out = Some(bcast_comp);

            // ── sync ───────────────────────────────────────────────────────
            let (sync_beh, sync_server, sync_clients) = sync::new(
                peer_ids.clone(),
                p2p_ctx.clone(),
                &key,
                def_hash.clone(),
                VERSION.clone(),
            )
            .expect("sync::new requires local peer in peer set");
            sync_server_out = Some(sync_server);
            sync_clients_out = Some(sync_clients);

            // ── parsigex ───────────────────────────────────────────────────
            let parsigex_config = ParsexConfig::new(
                local_id,
                p2p_ctx.clone(),
                // Skip per-sig verification in parsigex; we verify before aggregation.
                std::sync::Arc::new(|_duty, _pk, _sig| Box::pin(async { Ok(()) })),
                // Accept any duty type/slot during DKG.
                std::sync::Arc::new(|_duty| true),
            );
            let (parsigex_beh, parsigex_handle) = ParsexBehaviour::new(parsigex_config);
            parsigex_handle_out = Some(parsigex_handle);

            // ── peerinfo ───────────────────────────────────────────────────
            let local_info = LocalPeerInfo::new(
                VERSION.to_string(),
                def_hash.clone(),
                "",    // git hash not tracked in pluto yet
                false, // builder api
                "",    // nickname
            );
            let peerinfo_config = PeerinfoConfig::new(local_info).with_peers(peer_ids.clone());
            let peerinfo_beh = PeerinfoBehaviour::new(local_id, peerinfo_config);

            // ── frost p2p ──────────────────────────────────────────────────
            let (frost_p2p_beh, frost_p2p_handle) = FrostP2PBehaviour::new();
            frost_p2p_handle_out = Some(frost_p2p_handle);

            builder.with_gater(conn_gater).with_inner(DkgBehaviour {
                relay: relay_client,
                relay_reservation: MutableRelayReservation::new(relays.clone()),
                relay_router: RelayRouter::new(relays.clone(), p2p_ctx, local_id),
                bcast: bcast_beh,
                sync: sync_beh,
                parsigex: parsigex_beh,
                peerinfo: peerinfo_beh,
                frost_p2p: frost_p2p_beh,
            })
        },
    )?;

    let bcast_comp = bcast_comp_out.expect("bcast component initialized");
    let sync_server = sync_server_out.expect("sync server initialized");
    let sync_clients = sync_clients_out.expect("sync clients initialized");
    let parsigex_handle = parsigex_handle_out.expect("parsigex handle initialized");
    let frost_p2p = frost_p2p_handle_out.expect("frost p2p handle initialized");

    let node_idx = definition.node_idx(&local_peer_id)?;

    // Spawn the swarm event loop.
    let swarm_task = tokio::spawn(run_swarm(node, ct));

    info!(
        peer_id = %local_peer_id,
        share_idx = node_idx.share_idx,
        "DKG node started"
    );

    Ok(NodeHandles {
        node_idx,
        bcast_comp,
        sync_server,
        sync_clients,
        parsigex_handle,
        frost_p2p,
        swarm_task,
    })
}

// ── Swarm event loop ────────────────────────────────────────────────────────

async fn run_swarm(mut node: Node<DkgBehaviour>, ct: CancellationToken) {
    loop {
        tokio::select! {
            _ = ct.cancelled() => {
                debug!("DKG swarm stopping (cancellation)");
                break;
            }
            event = node.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        DkgBehaviourEvent::Relay(relay::client::Event::ReservationReqAccepted { relay_peer_id, .. })
                    )) => {
                        debug!(%relay_peer_id, "Relay reservation accepted");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        debug!(%peer_id, "Connection established");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause: Some(err), .. } => {
                        debug!(%peer_id, err = %err, "Connection closed with error");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause: None, .. } => {
                        debug!(%peer_id, "Connection closed");
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        warn!(peer_id = ?peer_id, err = %error, "Outgoing connection error");
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Converts a [`Multiaddr`] to the string format expected by
/// [`bootnode::new_relays`]:
/// - HTTP/HTTPS relay multiaddrs (e.g. `/ip4/…/tcp/…/http`) are converted
///   back to URL strings (`http://…`).
/// - All other multiaddrs are returned as-is via `to_string()`.
fn multiaddr_to_relay_str(addr: &Multiaddr) -> String {
    let mut ip = String::new();
    let mut port: u16 = 0;
    let mut is_http = false;
    let mut is_https = false;

    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(a) => ip = a.to_string(),
            Protocol::Ip6(a) => ip = format!("[{a}]"),
            Protocol::Dns(h) | Protocol::Dns4(h) | Protocol::Dns6(h) => {
                ip = h.to_string();
            }
            Protocol::Tcp(p) => port = p,
            Protocol::Http => is_http = true,
            Protocol::Https => is_https = true,
            _ => {}
        }
    }

    if (is_http || is_https) && !ip.is_empty() {
        let scheme = if is_https { "https" } else { "http" };
        format!("{scheme}://{ip}:{port}")
    } else {
        addr.to_string()
    }
}
