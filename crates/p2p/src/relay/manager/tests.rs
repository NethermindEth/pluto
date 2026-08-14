use std::{collections::HashSet, str::FromStr};

use super::*;
use crate::relay::dial::RelayDialState;

fn addr(s: &str) -> Multiaddr {
    Multiaddr::from_str(s).expect("valid multiaddr")
}

fn manager() -> RelayManager {
    RelayManager::new(Vec::new(), P2PContext::new(Vec::<PeerId>::new()))
}

// ---- circuit_addrs -------------------------------------------------

#[test]
fn circuit_addrs_strips_existing_p2p_and_appends_relay_suffix() {
    let relay = PeerId::random();
    let transport = addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{relay}"));

    let out = RelayManager::circuit_addrs(relay, &[transport]);

    let expected = addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{relay}/p2p-circuit"));
    assert_eq!(out, vec![expected]);
}

#[test]
fn circuit_addrs_handles_addr_without_existing_p2p_component() {
    let relay = PeerId::random();
    let transport = addr("/ip4/10.0.0.1/udp/9000/quic-v1");

    let out = RelayManager::circuit_addrs(relay, &[transport]);

    let expected = addr(&format!(
        "/ip4/10.0.0.1/udp/9000/quic-v1/p2p/{relay}/p2p-circuit"
    ));
    assert_eq!(out, vec![expected]);
}

#[test]
fn circuit_addrs_preserves_input_order_for_multiple_addrs() {
    let relay = PeerId::random();
    let other = PeerId::random();
    let inputs = vec![
        addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{other}")),
        addr("/ip4/10.0.0.1/udp/9000/quic-v1"),
    ];

    let out = RelayManager::circuit_addrs(relay, &inputs);

    assert_eq!(
        out,
        vec![
            addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{relay}/p2p-circuit")),
            addr(&format!(
                "/ip4/10.0.0.1/udp/9000/quic-v1/p2p/{relay}/p2p-circuit"
            )),
        ]
    );
}

#[test]
fn circuit_addrs_empty_input_yields_empty_output() {
    let relay = PeerId::random();
    let out = RelayManager::circuit_addrs(relay, &[]);
    assert!(out.is_empty());
}

// ---- relay_id_from_circuit_addr -----------------------------------

#[test]
fn relay_id_from_circuit_addr_extracts_last_p2p_before_circuit() {
    let relay = PeerId::random();
    let circuit = addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{relay}/p2p-circuit"));

    assert_eq!(
        RelayManager::relay_id_from_circuit_addr(&circuit),
        Some(relay)
    );
}

#[test]
fn relay_id_from_circuit_addr_ignores_target_p2p_after_circuit() {
    // Full circuit-dial form `/.../p2p/<relay>/p2p-circuit/p2p/<target>`
    // must return the relay id (before `/p2p-circuit`), not the target.
    let relay = PeerId::random();
    let target = PeerId::random();
    let circuit = addr(&format!(
        "/ip4/127.0.0.1/tcp/9000/p2p/{relay}/p2p-circuit/p2p/{target}"
    ));

    assert_eq!(
        RelayManager::relay_id_from_circuit_addr(&circuit),
        Some(relay)
    );
}

#[test]
fn relay_id_from_circuit_addr_returns_none_when_no_circuit_component() {
    let peer = PeerId::random();
    let plain = addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{peer}"));

    assert_eq!(RelayManager::relay_id_from_circuit_addr(&plain), None);
}

#[test]
fn relay_id_from_circuit_addr_returns_none_when_circuit_has_no_preceding_p2p() {
    let bare = addr("/ip4/127.0.0.1/tcp/9000/p2p-circuit");
    assert_eq!(RelayManager::relay_id_from_circuit_addr(&bare), None);
}

// ---- peer_circuit_addrs -------------------------------------------

#[test]
fn peer_circuit_addrs_returns_empty_when_no_relays_reserved() {
    let mgr = manager();
    let target = PeerId::random();
    assert!(mgr.peer_circuit_addrs(&target).is_empty());
}

#[test]
fn peer_circuit_addrs_ignores_relays_in_dialing_or_established() {
    let mut mgr = manager();
    let target = PeerId::random();
    let dialing = PeerId::random();
    let established = PeerId::random();

    mgr.connection_states
        .insert(dialing, RelayConnectionState::Dialing);
    mgr.relay_addrs
        .insert(dialing, vec![addr("/ip4/10.0.0.1/tcp/9000")]);
    mgr.connection_states
        .insert(established, RelayConnectionState::Established);
    mgr.relay_addrs
        .insert(established, vec![addr("/ip4/10.0.0.2/tcp/9000")]);

    assert!(mgr.peer_circuit_addrs(&target).is_empty());
}

#[test]
fn peer_circuit_addrs_skips_reserved_relay_without_tracked_addrs() {
    let mut mgr = manager();
    let target = PeerId::random();
    let relay = PeerId::random();

    mgr.connection_states
        .insert(relay, RelayConnectionState::Reserved);
    // No entry in relay_addrs: the relay is reserved but we have no
    // transport addrs to build a circuit through it.

    assert!(mgr.peer_circuit_addrs(&target).is_empty());
}

#[test]
fn peer_circuit_addrs_builds_one_circuit_per_reserved_relay_addr() {
    let mut mgr = manager();
    let target = PeerId::random();
    let relay = PeerId::random();

    let relay_addrs = vec![
        // With and without trailing /p2p/<relay> — both should produce the
        // same canonical circuit form.
        addr(&format!("/ip4/10.0.0.1/tcp/9000/p2p/{relay}")),
        addr("/ip4/10.0.0.1/udp/9000/quic-v1"),
    ];
    mgr.connection_states
        .insert(relay, RelayConnectionState::Reserved);
    mgr.relay_addrs.insert(relay, relay_addrs);

    let out = mgr.peer_circuit_addrs(&target);

    let expected = vec![
        addr(&format!(
            "/ip4/10.0.0.1/tcp/9000/p2p/{relay}/p2p-circuit/p2p/{target}"
        )),
        addr(&format!(
            "/ip4/10.0.0.1/udp/9000/quic-v1/p2p/{relay}/p2p-circuit/p2p/{target}"
        )),
    ];
    assert_eq!(out, expected);
}

#[test]
fn peer_circuit_addrs_aggregates_across_multiple_reserved_relays() {
    let mut mgr = manager();
    let target = PeerId::random();
    let relay_a = PeerId::random();
    let relay_b = PeerId::random();

    mgr.connection_states
        .insert(relay_a, RelayConnectionState::Reserved);
    mgr.relay_addrs
        .insert(relay_a, vec![addr("/ip4/10.0.0.1/tcp/9000")]);
    mgr.connection_states
        .insert(relay_b, RelayConnectionState::Reserved);
    mgr.relay_addrs
        .insert(relay_b, vec![addr("/ip4/10.0.0.2/tcp/9000")]);

    let out: HashSet<Multiaddr> = mgr.peer_circuit_addrs(&target).into_iter().collect();

    let expected: HashSet<Multiaddr> = [
        addr(&format!(
            "/ip4/10.0.0.1/tcp/9000/p2p/{relay_a}/p2p-circuit/p2p/{target}"
        )),
        addr(&format!(
            "/ip4/10.0.0.2/tcp/9000/p2p/{relay_b}/p2p-circuit/p2p/{target}"
        )),
    ]
    .into_iter()
    .collect();
    assert_eq!(out, expected);
}

// ---- queue_relay_update -------------------------------------------

fn relay_peer(id: PeerId, addrs: Vec<Multiaddr>) -> Peer {
    Peer {
        id,
        addresses: addrs,
        index: 0,
        name: crate::name::peer_name(&id),
    }
}

#[tokio::test]
async fn queue_relay_update_first_seen_starts_dial_campaign() {
    let mut mgr = manager();
    let relay_id = PeerId::random();
    let addrs = vec![addr("/ip4/10.0.0.1/tcp/9000")];

    mgr.queue_relay_update(relay_peer(relay_id, addrs.clone()));

    assert!(mgr.dial_states.contains_key(&relay_id));
    assert_eq!(
        mgr.connection_states.get(&relay_id),
        Some(&RelayConnectionState::Dialing)
    );
    assert_eq!(mgr.relay_addrs.get(&relay_id), Some(&addrs));
}

#[tokio::test]
async fn queue_relay_update_refreshes_inflight_addrs_without_resetting_backoff() {
    let mut mgr = manager();
    let relay_id = PeerId::random();

    mgr.queue_relay_update(relay_peer(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]));
    // Pretend the dial state has already retried a few times.
    mgr.dial_states.get_mut(&relay_id).unwrap().retry_count = 7;

    let new_addrs = vec![
        addr("/ip4/10.0.0.1/tcp/9000"),
        addr("/ip4/10.0.0.2/tcp/9000"),
    ];
    mgr.queue_relay_update(relay_peer(relay_id, new_addrs.clone()));

    let state = mgr.dial_states.get(&relay_id).unwrap();
    assert_eq!(state.addrs, new_addrs);
    assert_eq!(
        state.retry_count, 7,
        "backoff schedule must survive refresh"
    );
    assert_eq!(mgr.relay_addrs.get(&relay_id), Some(&new_addrs));
}

#[tokio::test]
async fn queue_relay_update_no_op_when_relay_already_connected() {
    let mut mgr = manager();
    let relay_id = PeerId::random();
    mgr.connection_states
        .insert(relay_id, RelayConnectionState::Reserved);

    let new_addrs = vec![addr("/ip4/10.0.0.99/tcp/9000")];
    mgr.queue_relay_update(relay_peer(relay_id, new_addrs.clone()));

    assert!(
        !mgr.dial_states.contains_key(&relay_id),
        "no dial campaign while connected"
    );
    // Connection state untouched.
    assert_eq!(
        mgr.connection_states.get(&relay_id),
        Some(&RelayConnectionState::Reserved)
    );
    // relay_addrs still gets refreshed so we have the latest list ready
    // for redial after a disconnect.
    assert_eq!(mgr.relay_addrs.get(&relay_id), Some(&new_addrs));
}

// ---- state machine: on_connection_established ----------------------

#[tokio::test]
async fn on_connection_established_relay_promotes_to_established_and_queues_listen() {
    let mut mgr = manager();
    let relay_id = PeerId::random();
    let relay_addrs = vec![
        addr("/ip4/10.0.0.1/tcp/9000"),
        addr("/ip4/10.0.0.1/udp/9000/quic-v1"),
    ];

    mgr.queue_relay_update(relay_peer(relay_id, relay_addrs.clone()));
    mgr.events.clear();
    mgr.on_connection_established(relay_id);

    assert!(!mgr.dial_states.contains_key(&relay_id));
    assert_eq!(
        mgr.connection_states.get(&relay_id),
        Some(&RelayConnectionState::Established)
    );
    let listen_count = mgr
        .events
        .iter()
        .filter(|e| matches!(e, ToSwarm::ListenOn { .. }))
        .count();
    // Exactly one circuit listener regardless of how many transport addrs the
    // relay has: libp2p keeps a single reservation per relay connection, so
    // additional listeners would displace each other.
    assert_eq!(listen_count, 1);
    let relay_connected = mgr.events.iter().any(|e| {
        matches!(
            e,
            ToSwarm::GenerateEvent(RelayManagerEvent::RelayConnected(id)) if *id == relay_id
        )
    });
    assert!(relay_connected, "RelayConnected event must be emitted");
}

#[tokio::test]
async fn on_connection_established_cluster_peer_drops_dial_state() {
    let mut mgr = manager();
    let target = PeerId::random();
    // Seed a peer-routing dial state (skipping upsert which requires
    // reserved relays).
    mgr.dial_states.insert(
        target,
        RelayDialState::new(
            RelayDialType::ClusterPeer,
            target,
            vec![addr("/ip4/10.0.0.1/tcp/9000/p2p-circuit")],
        ),
    );

    mgr.on_connection_established(target);

    assert!(!mgr.dial_states.contains_key(&target));
    let routed = mgr.events.iter().any(|e| {
        matches!(
            e,
            ToSwarm::GenerateEvent(RelayManagerEvent::PeerRoutedConnected(id)) if *id == target
        )
    });
    assert!(routed, "PeerRoutedConnected event must be emitted");
}

// ---- state machine: on_new_listen_addr -----------------------------

#[tokio::test]
async fn on_new_listen_addr_promotes_established_to_reserved() {
    let mut mgr = manager();
    let relay_id = PeerId::random();
    mgr.connection_states
        .insert(relay_id, RelayConnectionState::Established);
    mgr.relay_addrs
        .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

    let circuit = addr(&format!(
        "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit"
    ));
    mgr.on_new_listen_addr(&circuit);

    assert_eq!(
        mgr.connection_states.get(&relay_id),
        Some(&RelayConnectionState::Reserved)
    );
    let reserved = mgr.events.iter().any(|e| {
        matches!(
            e,
            ToSwarm::GenerateEvent(RelayManagerEvent::RelayReserved(id)) if *id == relay_id
        )
    });
    assert!(reserved);
}

// ---- state machine: on_expired_listen_addr -------------------------

#[tokio::test]
async fn on_expired_listen_addr_demotes_when_last_confirmed_circuit_expires() {
    let mut mgr = manager();
    let relay_id = PeerId::random();
    mgr.connection_states
        .insert(relay_id, RelayConnectionState::Established);
    mgr.relay_addrs
        .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

    let circuit = addr(&format!(
        "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit"
    ));
    mgr.on_new_listen_addr(&circuit);
    assert_eq!(
        mgr.connection_states.get(&relay_id),
        Some(&RelayConnectionState::Reserved)
    );

    mgr.on_expired_listen_addr(&circuit);

    assert_eq!(
        mgr.connection_states.get(&relay_id),
        Some(&RelayConnectionState::Established)
    );
    let lost = mgr.events.iter().any(|e| {
        matches!(
            e,
            ToSwarm::GenerateEvent(RelayManagerEvent::RelayReservationLost(id))
                if *id == relay_id
        )
    });
    assert!(lost, "RelayReservationLost must be emitted on demote");
}

#[tokio::test]
async fn on_expired_listen_addr_ignores_unconfirmed_sibling_listener_expiry() {
    // Regression for the boot race: one circuit listener confirms
    // (NewListenAddr) and a sibling listener that never confirmed expires
    // moments later. The relay must stay Reserved and keep routing peers —
    // demoting here partitioned the node for a full watchdog cycle.
    let mut mgr = manager();
    let relay_id = PeerId::random();
    let target = PeerId::random();
    mgr.connection_states
        .insert(relay_id, RelayConnectionState::Established);
    mgr.relay_addrs.insert(
        relay_id,
        vec![
            addr("/ip4/10.0.0.1/tcp/9000"),
            addr("/ip4/10.0.0.1/udp/9000/quic-v1"),
        ],
    );

    let confirmed = addr(&format!(
        "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit"
    ));
    let unconfirmed = addr(&format!(
        "/ip4/10.0.0.1/udp/9000/quic-v1/p2p/{relay_id}/p2p-circuit"
    ));
    mgr.on_new_listen_addr(&confirmed);
    // A peer routing campaign armed through the reserved relay.
    mgr.upsert_peer_dial(target);
    assert!(mgr.dial_states.contains_key(&target));

    mgr.on_expired_listen_addr(&unconfirmed);

    assert_eq!(
        mgr.connection_states.get(&relay_id),
        Some(&RelayConnectionState::Reserved),
        "expiry of a never-confirmed listener must not demote the relay"
    );
    assert!(
        mgr.dial_states.contains_key(&target),
        "peer routing campaigns must survive the sibling-listener expiry"
    );
    let lost = mgr.events.iter().any(|e| {
        matches!(
            e,
            ToSwarm::GenerateEvent(RelayManagerEvent::RelayReservationLost(_))
        )
    });
    assert!(
        !lost,
        "no ReservationLost while a confirmed circuit remains"
    );
}

#[tokio::test]
async fn on_expired_listen_addr_drops_peer_dials_with_no_route_left() {
    let mut mgr = manager();
    let relay_id = PeerId::random();
    let target = PeerId::random();

    // Single reserved relay supporting a peer-routing dial.
    mgr.connection_states
        .insert(relay_id, RelayConnectionState::Established);
    mgr.relay_addrs
        .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);
    let circuit = addr(&format!(
        "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit"
    ));
    mgr.on_new_listen_addr(&circuit);
    mgr.dial_states.insert(
        target,
        RelayDialState::new(
            RelayDialType::ClusterPeer,
            target,
            vec![addr(&format!(
                "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit/p2p/{target}"
            ))],
        ),
    );

    mgr.on_expired_listen_addr(&circuit);

    assert!(
        !mgr.dial_states.contains_key(&target),
        "peer dial state must be dropped once no reserved relay can route to it"
    );
}

#[tokio::test]
async fn redial_relay_clears_confirmed_circuits() {
    // The transport connection dropping kills every circuit listener; stale
    // confirmed addrs must not keep a future Reserved state alive across
    // reconnects.
    let mut mgr = manager();
    let relay_id = PeerId::random();
    mgr.connection_states
        .insert(relay_id, RelayConnectionState::Established);
    mgr.relay_addrs
        .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);
    let circuit = addr(&format!(
        "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit"
    ));
    mgr.on_new_listen_addr(&circuit);

    mgr.on_connection_closed(relay_id);

    assert!(
        mgr.reserved_addrs
            .get(&relay_id)
            .is_none_or(HashSet::is_empty),
        "confirmed circuit addrs must be cleared on relay disconnect"
    );
}

// ---- state machine: on_connection_closed ---------------------------

#[tokio::test]
async fn on_connection_closed_reserved_relay_emits_lost_before_disconnected() {
    let mut mgr = manager();
    let relay_id = PeerId::random();
    mgr.connection_states
        .insert(relay_id, RelayConnectionState::Reserved);
    mgr.relay_addrs
        .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

    mgr.on_connection_closed(relay_id);

    let lost_idx = mgr.events.iter().position(|e| {
        matches!(
            e,
            ToSwarm::GenerateEvent(RelayManagerEvent::RelayReservationLost(id))
                if *id == relay_id
        )
    });
    let disc_idx = mgr.events.iter().position(|e| {
        matches!(
            e,
            ToSwarm::GenerateEvent(RelayManagerEvent::RelayDisconnected(id)) if *id == relay_id
        )
    });
    let lost = lost_idx.expect("RelayReservationLost must fire when prev state was Reserved");
    let disc = disc_idx.expect("RelayDisconnected must fire on relay close");
    assert!(lost < disc, "ReservationLost must precede Disconnected");
    assert_eq!(
        mgr.connection_states.get(&relay_id),
        Some(&RelayConnectionState::Dialing),
        "redial campaign must arm"
    );
    assert!(mgr.dial_states.contains_key(&relay_id));
}

#[tokio::test]
async fn on_connection_closed_established_relay_skips_reservation_lost() {
    let mut mgr = manager();
    let relay_id = PeerId::random();
    mgr.connection_states
        .insert(relay_id, RelayConnectionState::Established);
    mgr.relay_addrs
        .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

    mgr.on_connection_closed(relay_id);

    let lost = mgr.events.iter().any(|e| {
        matches!(
            e,
            ToSwarm::GenerateEvent(RelayManagerEvent::RelayReservationLost(_))
        )
    });
    assert!(
        !lost,
        "no ReservationLost event when prev state wasn't Reserved"
    );
}

// ---- on_dial_failure: Skipped path --------------------------------

fn skipped_dial_error() -> DialError {
    DialError::DialPeerConditionFalse(
        libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing,
    )
}

/// Records an active connection to `peer` in the manager's peer store, as
/// `conn_logger` would on `ConnectionEstablished`.
fn record_connection(mgr: &RelayManager, peer: PeerId) {
    mgr.p2p_context
        .peer_store_write_lock()
        .add_peer(crate::p2p_context::Peer {
            id: peer,
            connection_id: libp2p::swarm::ConnectionId::new_unchecked(1),
            remote_addr: addr("/ip4/10.0.0.9/tcp/9000"),
        });
}

#[tokio::test]
async fn on_dial_failure_skipped_connected_cluster_peer_drops_dial_state() {
    let mut mgr = manager();
    let target = PeerId::random();
    record_connection(&mgr, target);
    mgr.dial_states.insert(
        target,
        RelayDialState::new(
            RelayDialType::ClusterPeer,
            target,
            vec![addr("/ip4/10.0.0.1/tcp/9000")],
        ),
    );

    mgr.on_dial_failure(Some(target), &skipped_dial_error());

    assert!(
        !mgr.dial_states.contains_key(&target),
        "cluster-peer dial state must be dropped on Skipped while connected"
    );
}

#[tokio::test]
async fn on_dial_failure_skipped_disconnected_cluster_peer_keeps_campaign() {
    // Regression for the boot-race wedge: dial #2 of a campaign is rejected
    // with DialPeerConditionFalse because dial #1 is still negotiating its
    // relay circuit. Dropping the campaign here orphans the peer if dial #1
    // then fails (a never-established connection produces no
    // ConnectionClosed, and force-direct skips zero-connection peers).
    let mut mgr = manager();
    let target = PeerId::random();
    mgr.dial_states.insert(
        target,
        RelayDialState::new(
            RelayDialType::ClusterPeer,
            target,
            vec![addr("/ip4/10.0.0.1/tcp/9000")],
        ),
    );

    mgr.on_dial_failure(Some(target), &skipped_dial_error());

    assert!(
        mgr.dial_states.contains_key(&target),
        "campaign must stay armed while the peer has no active connection"
    );
}

#[tokio::test]
async fn on_dial_failure_skipped_relay_keeps_dial_state() {
    // Regression for the wedge bug: keep the campaign armed so backoff
    // continues to retry until libp2p surfaces the connection state.
    let mut mgr = manager();
    let relay_id = PeerId::random();
    mgr.connection_states
        .insert(relay_id, RelayConnectionState::Dialing);
    mgr.dial_states.insert(
        relay_id,
        RelayDialState::new(
            RelayDialType::RelayServer,
            relay_id,
            vec![addr("/ip4/10.0.0.1/tcp/9000")],
        ),
    );

    mgr.on_dial_failure(Some(relay_id), &skipped_dial_error());

    assert!(
        mgr.dial_states.contains_key(&relay_id),
        "relay dial state must survive Skipped so backoff can retry"
    );
    assert_eq!(
        mgr.connection_states.get(&relay_id),
        Some(&RelayConnectionState::Dialing),
        "connection state must still be Dialing"
    );
}

// ---- upsert_peer_dial ---------------------------------------------

#[tokio::test]
async fn upsert_peer_dial_preserves_backoff_when_addrs_unchanged() {
    let mut mgr = manager();
    let target = PeerId::random();
    let relay = PeerId::random();
    mgr.connection_states
        .insert(relay, RelayConnectionState::Reserved);
    mgr.relay_addrs
        .insert(relay, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

    mgr.upsert_peer_dial(target);
    let inserted_count = mgr.dial_states.get(&target).map(|s| s.retry_count);
    // Pretend the dial has retried.
    if let Some(s) = mgr.dial_states.get_mut(&target) {
        s.retry_count = 5;
    }
    mgr.upsert_peer_dial(target);
    let after = mgr.dial_states.get(&target).map(|s| s.retry_count);
    assert_eq!(inserted_count, Some(0));
    assert_eq!(
        after,
        Some(5),
        "addr-set unchanged: existing dial state (and its backoff) must be preserved"
    );
}

#[tokio::test]
async fn upsert_peer_dial_resets_backoff_when_addrs_change() {
    let mut mgr = manager();
    let target = PeerId::random();
    let relay_a = PeerId::random();
    let relay_b = PeerId::random();
    mgr.connection_states
        .insert(relay_a, RelayConnectionState::Reserved);
    mgr.relay_addrs
        .insert(relay_a, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

    mgr.upsert_peer_dial(target);
    if let Some(s) = mgr.dial_states.get_mut(&target) {
        s.retry_count = 5;
    }

    // Reserve a second relay → new circuit addr → addr-set changes.
    mgr.connection_states
        .insert(relay_b, RelayConnectionState::Reserved);
    mgr.relay_addrs
        .insert(relay_b, vec![addr("/ip4/10.0.0.2/tcp/9000")]);
    mgr.upsert_peer_dial(target);

    assert_eq!(
        mgr.dial_states.get(&target).map(|s| s.retry_count),
        Some(0),
        "addr-set changed: dial state (and backoff) must be replaced"
    );
}

#[tokio::test]
async fn upsert_peer_dial_drops_stale_state_when_no_route_left() {
    let mut mgr = manager();
    let target = PeerId::random();
    let relay = PeerId::random();
    mgr.connection_states
        .insert(relay, RelayConnectionState::Reserved);
    mgr.relay_addrs
        .insert(relay, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

    mgr.upsert_peer_dial(target);
    assert!(mgr.dial_states.contains_key(&target));

    // Demote the only reserved relay → no circuit addrs left.
    mgr.connection_states
        .insert(relay, RelayConnectionState::Established);
    mgr.upsert_peer_dial(target);

    assert!(
        !mgr.dial_states.contains_key(&target),
        "no reserved relay can reach target: stale dial state must be dropped"
    );
}

// ---- sweep_disconnected_peers --------------------------------------

/// Manager with one reserved relay and the given known cluster peers.
fn manager_with_reserved_relay(known: Vec<PeerId>) -> RelayManager {
    let mut mgr = RelayManager::new(Vec::new(), P2PContext::new(known));
    let relay = PeerId::random();
    mgr.connection_states
        .insert(relay, RelayConnectionState::Reserved);
    mgr.relay_addrs
        .insert(relay, vec![addr("/ip4/10.0.0.1/tcp/9000")]);
    mgr
}

#[tokio::test]
async fn sweep_rearms_known_peer_with_no_connection_and_no_campaign() {
    // Regression for the boot-race wedge's terminal state: a known peer with
    // zero connections and no dial campaign must be picked up by the sweep.
    let target = PeerId::random();
    let mut mgr = manager_with_reserved_relay(vec![target]);

    mgr.sweep_disconnected_peers();

    assert!(
        mgr.dial_states.contains_key(&target),
        "sweep must re-arm a circuit dial for the unrouted peer"
    );
}

#[tokio::test]
async fn sweep_skips_connected_peers_and_in_flight_campaigns_and_self() {
    let connected = PeerId::random();
    let campaigning = PeerId::random();
    let local = PeerId::random();
    let mut mgr = manager_with_reserved_relay(vec![connected, campaigning, local]);
    mgr.p2p_context.set_local_peer_id(local);
    record_connection(&mgr, connected);
    mgr.dial_states.insert(
        campaigning,
        RelayDialState::new(
            RelayDialType::ClusterPeer,
            campaigning,
            vec![addr("/ip4/10.0.0.1/tcp/9000")],
        ),
    );
    let campaign_retry_count = 3;
    if let Some(s) = mgr.dial_states.get_mut(&campaigning) {
        s.retry_count = campaign_retry_count;
    }

    mgr.sweep_disconnected_peers();

    assert!(
        !mgr.dial_states.contains_key(&connected),
        "connected peer must not get a dial campaign"
    );
    assert!(
        !mgr.dial_states.contains_key(&local),
        "self must never be dialed"
    );
    assert_eq!(
        mgr.dial_states.get(&campaigning).map(|s| s.retry_count),
        Some(campaign_retry_count),
        "existing campaign (and its backoff) must be left untouched"
    );
}

#[tokio::test(start_paused = true)]
async fn poll_fires_swept_peer_dial_within_the_same_watchdog_pass() {
    // The sweep runs on the watchdog tick inside poll(); the dial state it
    // inserts must be polled in the same pass. If it isn't, no waker is
    // registered for it and — with nothing else waking the swarm — the dial
    // waits a full extra watchdog tick.
    let target = PeerId::random();
    let mut mgr = manager_with_reserved_relay(vec![target]);
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Drain until Pending: initialises the watchdog.
    while mgr.poll(&mut cx).is_ready() {}

    tokio::time::advance(ESTABLISHED_WATCHDOG_TICK).await;

    let mut saw_dial = false;
    while let Poll::Ready(ev) = mgr.poll(&mut cx) {
        if matches!(ev, ToSwarm::Dial { .. }) {
            saw_dial = true;
        }
    }
    assert!(
        saw_dial,
        "the swept peer's dial must fire in the same watchdog pass"
    );
}

// ---- relay_connections metric --------------------------------------

/// Current `p2p_relay_connections` value for a relay, or `None` if it has no
/// series yet. Uses `get` rather than indexing so it doesn't create one.
fn relay_connections(relay_id: PeerId) -> Option<i64> {
    P2P_METRICS
        .relay_connections
        .get(&peer_name(&relay_id))
        .map(vise::Gauge::get)
}

#[tokio::test]
async fn relay_connections_tracks_reservation_lifecycle() {
    let mut mgr = manager();
    let relay_id = PeerId::random();
    let circuit = addr(&format!(
        "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit"
    ));

    assert_eq!(
        relay_connections(relay_id),
        None,
        "no series before the relay is known"
    );

    // Dialing.
    mgr.queue_relay_update(relay_peer(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]));
    assert_eq!(relay_connections(relay_id), Some(0));

    mgr.on_connection_established(relay_id);
    assert_eq!(
        relay_connections(relay_id),
        Some(0),
        "a transport connection alone is not a reservation"
    );

    // Reservation confirmed.
    mgr.on_new_listen_addr(&circuit);
    assert_eq!(relay_connections(relay_id), Some(1));

    // Reservation lost without a ConnectionClosed: libp2p owns refreshes.
    mgr.on_expired_listen_addr(&circuit);
    assert_eq!(
        mgr.connection_states.get(&relay_id),
        Some(&RelayConnectionState::Established),
        "precondition: demoted without losing the transport connection"
    );
    assert_eq!(relay_connections(relay_id), Some(0));

    // Transport drops → redial campaign.
    mgr.on_connection_closed(relay_id);
    assert_eq!(relay_connections(relay_id), Some(0));

    // Reconnect and re-reserve.
    mgr.on_connection_established(relay_id);
    mgr.on_new_listen_addr(&circuit);
    assert_eq!(relay_connections(relay_id), Some(1));
}

#[tokio::test]
async fn relay_connections_cleared_when_relay_state_is_dropped() {
    // `redial_relay` drops the state without `set_relay_state` when the relay's
    // addresses are no longer tracked.
    let mut mgr = manager();
    let relay_id = PeerId::random();
    mgr.set_relay_state(relay_id, RelayConnectionState::Reserved);
    assert_eq!(relay_connections(relay_id), Some(1));

    mgr.on_connection_closed(relay_id);

    assert!(!mgr.connection_states.contains_key(&relay_id));
    assert_eq!(relay_connections(relay_id), Some(0));
}

#[tokio::test]
async fn sweep_is_noop_without_reserved_relays() {
    let target = PeerId::random();
    let mut mgr = RelayManager::new(Vec::new(), P2PContext::new(vec![target]));

    mgr.sweep_disconnected_peers();

    assert!(
        !mgr.dial_states.contains_key(&target),
        "no reserved relay: nothing to arm"
    );
}
