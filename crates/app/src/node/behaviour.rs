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
use pluto_eth2api::EthBeaconNodeApiClient;
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
    /// Priority protocol request/response transport (backs infosync).
    pub priority: pluto_priority::p2p::Behaviour,
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
    /// Priority protocol component; started by the caller.
    pub priority: Arc<pluto_priority::Component>,
    /// Expired-duty receiver for `priority`; move-only, consumed once by
    /// `Component::start`.
    pub priority_expired_rx: tokio::sync::mpsc::Receiver<pluto_core::types::Duty>,
    /// Infosync component driving the per-epoch priority exchange.
    pub infosync: Arc<pluto_infosync::Component>,
}

/// Inputs to [`wire_p2p`], grouped to keep the aggregating call site readable.
pub(crate) struct WireP2PParams {
    pub key: k256::SecretKey,
    pub p2p_config: pluto_p2p::config::P2PConfig,
    pub peers: Vec<Peer>,
    pub consensus: Arc<qbft::Consensus>,
    pub min_required: i64,
    pub deadline_calc: Arc<dyn pluto_core::deadline::DeadlineCalculator>,
    pub feature_set: Arc<pluto_featureset::FeatureSet>,
    pub duty_gater: DutyGaterFn,
    pub eth2_cl: EthBeaconNodeApiClient,
    pub pub_shares_by_key: HashMap<PubKey, HashMap<u64, PublicKey>>,
    pub lock_hash: Vec<u8>,
    pub builder_enabled: bool,
    pub nickname: String,
    pub cancellation: CancellationToken,
}

/// Composes the core behaviours and builds the libp2p [`Node`].
// TODO(#402 part B): QUIC transport (featureset-gated off at v1.7.1) and
// bandwidth metrics.
pub(crate) async fn wire_p2p(
    params: WireP2PParams,
) -> Result<(Node<CoreBehaviour>, CoreHandles), AppError> {
    let WireP2PParams {
        key,
        p2p_config,
        peers,
        consensus,
        min_required,
        deadline_calc,
        feature_set,
        duty_gater,
        eth2_cl,
        pub_shares_by_key,
        lock_hash,
        builder_enabled,
        nickname,
        cancellation,
    } = params;

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

    // Priority rides the same QBFT consensus; clone before it moves into the
    // QBFT behaviour below.
    let priority_consensus: Arc<dyn pluto_priority::Consensus> = consensus.clone();
    let priority_cancellation = cancellation.clone();

    // QBFT consensus transport. `Behaviour::new` errors if the local peer id is
    // not present in the configured cluster peer list.
    let (consensus_comp, consensus_handle) = qbft::p2p::Behaviour::new(qbft::p2p::Config {
        consensus,
        p2p_context: p2p_context.clone(),
        local_peer_id,
        cancellation,
    })?;

    // Peer metadata exchange. Use the Charon-compatible short git hash: Charon
    // rejects a peer's whole peerinfo record if the git hash isn't `^[0-9a-f]{7}$`,
    // so this always advertises a well-formed hash even in git-less builds.
    let git_hash = pluto_core::version::git_commit_hash_short();
    let peerinfo_config = peerinfo::Config::new(LocalPeerInfo::new(
        pluto_core::version::VERSION.to_string(),
        lock_hash,
        git_hash,
        builder_enabled,
        nickname,
    ))
    .with_peers(peer_ids.clone());
    let peerinfo_comp = peerinfo::Behaviour::new(local_peer_id, peerinfo_config);

    // Priority + infosync: per-epoch negotiation of supported
    // versions/protocols/proposal types. The 6s exchange timeout (half a slot)
    // matches Charon; `new_component` fails fast on a peer missing from the
    // shared `p2p_context`.
    let (priority_comp, priority_behaviour, priority_expired_rx) = pluto_priority::new_component(
        peer_ids.clone(),
        min_required,
        priority_consensus,
        std::time::Duration::from_secs(6),
        key.clone(),
        deadline_calc,
        p2p_context.clone(),
        priority_cancellation,
    )?;
    let priority_comp = Arc::new(priority_comp);

    let infosync = Arc::new(pluto_infosync::Component::new(
        Arc::clone(&priority_comp),
        pluto_core::version::SUPPORTED.to_vec(),
        local_protocols(),
        local_proposal_types(builder_enabled),
        &feature_set,
    ));

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
                priority: priority_behaviour,
            })
        },
    )?;

    let handles = CoreHandles {
        parsigex: parsigex_handle,
        consensus: consensus_handle,
        p2p_context: p2p_context_for_handle,
        priority: priority_comp,
        priority_expired_rx,
        infosync,
    };

    Ok((node, handles))
}

/// Advertised proposal types in precedence order: builder first when enabled,
/// full always last as the fallback.
fn local_proposal_types(builder_enabled: bool) -> Vec<pluto_core::types::ProposalType> {
    let mut proposal_types = Vec::new();
    if builder_enabled {
        proposal_types.push(pluto_core::types::ProposalType::Builder);
    }
    proposal_types.push(pluto_core::types::ProposalType::Full);
    proposal_types
}

/// Advertised protocols in precedence order: consensus, parsigex, peerinfo,
/// priority.
// TODO(#402 part B): reorder by the cluster-preferred / CLI consensus protocol
// once those inputs exist, matching Go's `PrioritizeProtocolsByName`.
fn local_protocols() -> Vec<String> {
    pluto_consensus::protocols::protocols()
        .iter()
        .map(|p| p.to_string())
        .chain(pluto_parsigex::protocols().iter().map(|p| p.to_string()))
        .chain(pluto_peerinfo::protocols().iter().map(|p| p.to_string()))
        .chain(pluto_priority::protocols().iter().map(|p| p.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use pluto_core::types::ProposalType;

    use super::{local_proposal_types, local_protocols};

    #[test]
    fn proposal_types_put_builder_first_only_when_enabled() {
        assert_eq!(local_proposal_types(false), vec![ProposalType::Full]);
        assert_eq!(
            local_proposal_types(true),
            vec![ProposalType::Builder, ProposalType::Full],
        );
    }

    #[test]
    fn protocols_are_advertised_in_component_precedence_order() {
        // This ordering is what keeps pluto's info_sync result byte-identical
        // to Charon's; priority's absence is the bug this wiring fixes.
        let got = local_protocols();

        let index_of = |head: String| {
            got.iter()
                .position(|p| *p == head)
                .expect("protocol advertised")
        };
        let consensus = index_of(pluto_consensus::protocols::protocols()[0].to_string());
        let parsigex = index_of(pluto_parsigex::protocols()[0].to_string());
        let peerinfo = index_of(pluto_peerinfo::protocols()[0].to_string());
        let priority = index_of(pluto_priority::protocols()[0].to_string());

        assert!(consensus < parsigex);
        assert!(parsigex < peerinfo);
        assert!(peerinfo < priority);
    }
}
