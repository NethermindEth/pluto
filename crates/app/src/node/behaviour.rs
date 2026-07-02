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

use std::{collections::HashMap, sync::Arc};

use libp2p::swarm::NetworkBehaviour;
use pluto_consensus::qbft;
use pluto_core::{gater::DutyGaterFn, types::PubKey};
use pluto_crypto::types::PublicKey;
use pluto_eth2api::EthBeaconNodeApiClient;
use pluto_p2p::{
    gater,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::{self, Peer},
};
use pluto_parsigex as parsigex;
use pluto_peerinfo::{self as peerinfo, LocalPeerInfo};
use tokio_util::sync::CancellationToken;

use crate::node::AppError;

/// Composed network behaviour for the core duty workflow.
#[derive(NetworkBehaviour)]
pub(crate) struct CoreBehaviour {
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
}

/// Composes the core behaviours and builds the libp2p [`Node`].
// TODO(#402 part B): relay/NAT support (relay client + RelayManager), QUIC
// transport, and bandwidth metrics — start with TCP + no relay.
#[allow(
    clippy::too_many_arguments,
    reason = "wireP2P aggregates independent inputs; a config struct is deferred to part B when relay/priority inputs are added"
)]
pub(crate) fn wire_p2p(
    key: k256::SecretKey,
    p2p_config: pluto_p2p::config::P2PConfig,
    peers: Vec<Peer>,
    consensus: Arc<qbft::Consensus>,
    duty_gater: DutyGaterFn,
    eth2_cl: EthBeaconNodeApiClient,
    pub_shares_by_key: HashMap<PubKey, HashMap<u64, PublicKey>>,
    lock_hash: Vec<u8>,
    builder_enabled: bool,
    nickname: String,
    cancellation: CancellationToken,
) -> Result<(Node<CoreBehaviour>, CoreHandles), AppError> {
    let peer_ids = peers.iter().map(|peer| peer.id).collect::<Vec<_>>();
    let local_peer_id = peer::peer_id_from_key(key.public_key())?;

    peer::verify_p2p_key(&peers, &key)?;

    // TODO(#402 part B): relay/NAT support — use `new_conn_gater(peer_ids, relays)`
    // once relays are resolved. For minimal TCP-only wiring an open gater suffices
    // since the conn gater is only meaningful with relays.
    let conn_gater = gater::ConnGater::new_conn_gater(peer_ids.clone(), Vec::new());

    let p2p_context = P2PContext::new(peer_ids.clone());
    p2p_context.set_local_peer_id(local_peer_id);

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

    let handles = CoreHandles {
        parsigex: parsigex_handle,
        consensus: consensus_handle,
    };

    Ok((node, handles))
}
