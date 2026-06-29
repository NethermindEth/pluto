//! Composed P2P [`NetworkBehaviour`] for the core duty workflow.
//!
//! This is the Rust analog of Charon's `wireP2P`: it composes the three core
//! protocol behaviours (partial-signature exchange, QBFT consensus, peerinfo)
//! into a single libp2p behaviour and builds a [`Node`] driving it.
//!
//! Routing is push-based inside the individual behaviours (the QBFT p2p
//! [`Handler`](pluto_consensus::qbft::p2p) holds an `Arc<Consensus>` and calls
//! `consensus.handle()`; parsigex's [`Handle::subscribe`] dispatches inbound
//! partial signatures), so the swarm drive loop body can be empty for
//! correctness — see [`crate::node::drive_network`].

use std::sync::Arc;

use libp2p::swarm::NetworkBehaviour;
use pluto_consensus::qbft;
use pluto_core::gater::DutyGaterFn;
use pluto_p2p::{
    gater,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::{Peer, peer_id_from_key, verify_p2p_key},
};
use pluto_parsigex as parsigex;
use pluto_peerinfo::{self as peerinfo, LocalPeerInfo};
use tokio_util::sync::CancellationToken;

use crate::node::AppError;

/// Composed network behaviour for the core duty workflow.
#[derive(NetworkBehaviour)]
pub(crate) struct CoreBehaviour {
    /// Partial signature exchange between cluster peers.
    pub(crate) parsigex: parsigex::Behaviour,
    /// QBFT consensus message transport.
    pub(crate) consensus: qbft::p2p::Behaviour,
    /// Peer metadata exchange.
    pub(crate) peerinfo: peerinfo::Behaviour,
}

/// Async handles for driving the composed behaviour from the core workflow.
pub(crate) struct P2PHandles {
    /// Outbound partial-signature broadcast + inbound subscription handle.
    pub(crate) parsigex: parsigex::Handle,
    /// Outbound QBFT broadcast handle.
    pub(crate) consensus: qbft::p2p::Handle,
}

/// Inputs required to compose and build the core P2P node.
pub(crate) struct SetupP2PParams {
    /// Local secp256k1 P2P key.
    pub(crate) key: k256::SecretKey,
    /// P2P listen/advertise configuration.
    pub(crate) p2p_config: pluto_p2p::config::P2PConfig,
    /// Cluster peers (from the lock file).
    pub(crate) peers: Vec<Peer>,
    /// Already-constructed consensus component, shared with the core stitch.
    pub(crate) consensus: Arc<qbft::Consensus>,
    /// Duty admission gate, shared with parsigex.
    pub(crate) duty_gater: DutyGaterFn,
    /// Cluster lock hash (peerinfo + relay namespace).
    pub(crate) lock_hash: Vec<u8>,
    /// Whether the builder API is enabled (peerinfo advertisement).
    pub(crate) builder_enabled: bool,
    /// Human-readable node nickname.
    pub(crate) nickname: String,
    /// Cancellation token for inbound admission.
    pub(crate) cancellation: CancellationToken,
}

/// Composes the core behaviours and builds the libp2p [`Node`].
///
/// Models Charon's `wireP2P`; the QBFT consensus component is constructed by
/// the caller (so it can also be used for the core stitch) and the
/// broadcaster↔behaviour construction cycle is resolved by the caller via the
/// `Arc<OnceLock<Handle>>` pattern.
//
// TODO(#402 part B): relay/NAT support (relay client + RelayManager), QUIC
// transport, and bandwidth metrics — start with TCP + no relay.
pub(crate) fn setup_p2p(
    params: SetupP2PParams,
) -> Result<(Node<CoreBehaviour>, P2PHandles), AppError> {
    let SetupP2PParams {
        key,
        p2p_config,
        peers,
        consensus,
        duty_gater,
        lock_hash,
        builder_enabled,
        nickname,
        cancellation,
    } = params;

    let peer_ids = peers.iter().map(|peer| peer.id).collect::<Vec<_>>();
    let local_peer_id = peer_id_from_key(key.public_key())?;

    verify_p2p_key(&peers, &key)?;

    // TODO(#402 part B): relay/NAT support — use `new_conn_gater(peer_ids, relays)`
    // once relays are resolved. For minimal TCP-only wiring an open gater suffices
    // since the conn gater is only meaningful with relays.
    let conn_gater = gater::ConnGater::new_conn_gater(peer_ids.clone(), Vec::new());

    let p2p_context = P2PContext::new(peer_ids.clone());
    p2p_context.set_local_peer_id(local_peer_id);

    // Partial signature exchange.
    //
    // TODO(#402 part B): use an eth2-based verifier (`parsigex::NewEth2Verifier`
    // equivalent) keyed by the cluster pubshares instead of the always-accept
    // stub. No such constructor exists yet in pluto-parsigex.
    let parsigex_config = parsigex::Config::new(
        local_peer_id,
        p2p_context.clone(),
        Arc::new(|_duty, _pk, _sig| Box::pin(async { Ok(()) })),
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

    let node = Node::new(
        p2p_config,
        key,
        NodeType::TCP,
        false,
        p2p_context,
        |builder, _keypair, _relay_client| {
            builder.with_gater(conn_gater).with_inner(CoreBehaviour {
                parsigex: parsigex_comp,
                consensus: consensus_comp,
                peerinfo: peerinfo_comp,
            })
        },
    )?;

    let handles = P2PHandles {
        parsigex: parsigex_handle,
        consensus: consensus_handle,
    };

    Ok((node, handles))
}
