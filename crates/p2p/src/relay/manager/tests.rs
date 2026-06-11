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
    let relay_addrs = vec![addr("/ip4/10.0.0.1/tcp/9000")];

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
    assert_eq!(listen_count, relay_addrs.len());
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
async fn on_expired_listen_addr_demotes_reserved_and_emits_reservation_lost() {
    let mut mgr = manager();
    let relay_id = PeerId::random();
    mgr.connection_states
        .insert(relay_id, RelayConnectionState::Reserved);
    mgr.relay_addrs
        .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

    let circuit = addr(&format!(
        "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit"
    ));
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
async fn on_expired_listen_addr_drops_peer_dials_with_no_route_left() {
    let mut mgr = manager();
    let relay_id = PeerId::random();
    let target = PeerId::random();

    // Single reserved relay supporting a peer-routing dial.
    mgr.connection_states
        .insert(relay_id, RelayConnectionState::Reserved);
    mgr.relay_addrs
        .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);
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

    let circuit = addr(&format!(
        "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit"
    ));
    mgr.on_expired_listen_addr(&circuit);

    assert!(
        !mgr.dial_states.contains_key(&target),
        "peer dial state must be dropped once no reserved relay can route to it"
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

#[tokio::test]
async fn on_dial_failure_skipped_cluster_peer_drops_dial_state() {
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
        !mgr.dial_states.contains_key(&target),
        "cluster-peer dial state must be dropped on Skipped"
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
