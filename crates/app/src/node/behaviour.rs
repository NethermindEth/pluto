//! Composed P2P [`NetworkBehaviour`] for the core duty workflow.
//!
//! This is the Rust analog of Charon's `wireP2P`: it composes the relay
//! transport behaviours (relay client, [`RelayManager`], force-direct) with
//! the three core protocol behaviours (partial-signature exchange, QBFT
//! consensus, peerinfo) into a single libp2p behaviour and builds a [`Node`]
//! driving it. Relay reservation + routing is the cluster's only
//! peer-discovery path (lock ENRs carry no addresses), mirroring Charon's
//! `NewRelays` / `NewRelayReserver` / `NewRelayRouter` /
//! `ForceDirectConnections`.
//!
//! Routing is push-based inside the individual behaviours (the QBFT p2p
//! [`Handler`](pluto_consensus::qbft::p2p) holds an `Arc<Consensus>` and calls
//! `consensus.handle()`; parsigex's [`Handle::subscribe`] dispatches inbound
//! partial signatures), so the swarm drive loop body can be empty for
//! correctness — see [`crate::node::drive_network`].

use std::{collections::HashMap, sync::Arc};

use libp2p::{relay, swarm::NetworkBehaviour};
use pluto_consensus::qbft;
use pluto_core::{gater::DutyGaterFn, types::PubKey};
use pluto_crypto::types::PublicKey;
use pluto_eth2api::BeaconNodeClient;
use pluto_p2p::{
    bootnode,
    force_direct::ForceDirectBehaviour,
    gater,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::{self, Peer},
    relay::RelayManager,
};
use pluto_parsigex as parsigex;
use pluto_peerinfo::{self as peerinfo, LocalPeerInfo};
use tokio_util::sync::CancellationToken;

use crate::node::AppError;

/// Composed network behaviour for the core duty workflow.
#[derive(NetworkBehaviour)]
pub(crate) struct CoreBehaviour {
    /// Relay client transport (circuit reservations and relayed dials).
    pub relay: relay::client::Behaviour,
    /// Relay reservation lifecycle + relay-circuit peer routing (Charon's
    /// `NewRelayReserver` + `NewRelayRouter`).
    pub relay_manager: RelayManager,
    /// Upgrades relay-routed connections to direct ones (Charon's
    /// `ForceDirectConnections`).
    pub force_direct: ForceDirectBehaviour,
    /// Partial signature exchange between cluster peers.
    pub parsigex: parsigex::Behaviour,
    /// QBFT consensus message transport.
    pub consensus: qbft::p2p::Behaviour,
    /// Peer metadata exchange.
    pub peerinfo: peerinfo::Behaviour,
}

/// Async handles for driving the composed behaviour from the core workflow.
pub struct CoreHandles {
    /// Outbound partial-signature broadcast + inbound subscription handle.
    pub parsigex: parsigex::Handle,
    /// Outbound QBFT broadcast handle.
    pub consensus: qbft::p2p::Handle,
    /// Shared P2P runtime context (known peers + live connections), used by the
    /// monitoring API's readiness checker to compute quorum connectivity.
    pub p2p_context: P2PContext,
}

/// Composes the core behaviours and builds the libp2p [`Node`].
// TODO(#402 part B): QUIC transport (featureset-gated off at v1.7.1) and
// bandwidth metrics.
#[allow(
    clippy::too_many_arguments,
    reason = "wireP2P aggregates independent inputs; a config struct is deferred to part B when priority inputs are added"
)]
pub(crate) async fn wire_p2p(
    key: k256::SecretKey,
    p2p_config: pluto_p2p::config::P2PConfig,
    peers: Vec<Peer>,
    consensus: Arc<qbft::Consensus>,
    duty_gater: DutyGaterFn,
    eth2_cl: BeaconNodeClient,
    pub_shares_by_key: HashMap<PubKey, HashMap<u64, PublicKey>>,
    lock_hash: Vec<u8>,
    builder_enabled: bool,
    nickname: String,
    cancellation: CancellationToken,
) -> Result<(Node<CoreBehaviour>, CoreHandles), AppError> {
    let peer_ids = peers.iter().map(|peer| peer.id).collect::<Vec<_>>();
    let local_peer_id = peer::peer_id_from_key(key.public_key())?;

    // TODO: also send the post-#4130 `Cluster-Uuid` header (relay-side load
    // balancing), pending in pluto-p2p's `new_relays`.
    let relay_addrs = bootnode::relay_addrs_for_resolution(&p2p_config.relays);
    let relays = bootnode::new_relays(
        cancellation.clone(),
        &relay_addrs,
        &crate::utils::hex_7(&lock_hash),
    )
    .await?;

    // Closed gater: only cluster peers and the resolved relays may connect.
    let conn_gater = gater::ConnGater::new_conn_gater(peer_ids.clone(), relays.clone());

    let p2p_context = P2PContext::new(peer_ids.clone());
    p2p_context.set_local_peer_id(local_peer_id);

    // Keeps one circuit reservation alive per relay and continuously routes
    // cluster peers via relay circuit addresses; force-direct then upgrades
    // relayed connections to direct ones.
    let relay_manager = RelayManager::new(relays, p2p_context.clone());
    let force_direct = ForceDirectBehaviour::new(p2p_context.clone(), local_peer_id);

    // Partial signature exchange. Inbound partial signatures are verified
    // against the sender's public share for the duty via the eth2 verifier
    // (Charon `parsigex.NewEth2Verifier`).
    let parsigex_config = parsigex::Config::new(
        local_peer_id,
        p2p_context.clone(),
        parsigex::new_eth2_verifier(eth2_cl, pub_shares_by_key),
        duty_gater,
    );
    let (parsigex_comp, parsigex_handle) = parsigex::Behaviour::new(parsigex_config);

    // QBFT consensus transport. `Behaviour::new` errors if the local peer id is
    // not present in the configured cluster peer list.
    let (consensus_comp, consensus_handle) = qbft::p2p::Behaviour::new(qbft::p2p::Config {
        consensus,
        p2p_context: p2p_context.clone(),
        local_peer_id,
        cancellation,
    })?;

    // Peer metadata exchange.
    let (git_hash, _) = pluto_core::version::git_commit();
    let peerinfo_config = peerinfo::Config::new(LocalPeerInfo::new(
        pluto_core::version::VERSION.to_string(),
        lock_hash,
        git_hash,
        builder_enabled,
        nickname,
    ))
    .with_peers(peer_ids.clone());
    let peerinfo_comp = peerinfo::Behaviour::new(local_peer_id, peerinfo_config);

    // Clone the context before it is moved into the node so the readiness
    // checker observes the same shared peer/connection state the swarm updates.
    let p2p_context_for_handle = p2p_context.clone();

    let node = Node::new(
        p2p_config,
        key,
        NodeType::TCP,
        false,
        p2p_context,
        |builder, _keypair, relay_client| {
            builder.with_gater(conn_gater).with_inner(CoreBehaviour {
                relay: relay_client,
                relay_manager,
                force_direct,
                parsigex: parsigex_comp,
                consensus: consensus_comp,
                peerinfo: peerinfo_comp,
            })
        },
    )?;

    let handles = CoreHandles {
        parsigex: parsigex_handle,
        consensus: consensus_handle,
        p2p_context: p2p_context_for_handle,
    };

    Ok((node, handles))
}
