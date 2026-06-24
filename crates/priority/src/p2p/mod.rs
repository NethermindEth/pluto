//! libp2p request/response transport for the priority protocol.
//!
//! The transport is split into the user-facing [`Sender`] handle and the
//! libp2p-owned [`Behaviour`]/[`handler::Handler`] runtime objects. It performs
//! a single round-trip per exchange on the priority protocol:
//!
//! - Outbound: [`Sender::send_receive`] sends a [`PriorityMsg`] to a peer and
//!   resolves with that peer's [`PriorityMsg`] response.
//! - Inbound: a negotiated stream reads a [`PriorityMsg`], invokes the
//!   registered [`InboundHandler`] callback to produce a response, and writes
//!   it back. A `None` response closes the stream without replying.
//!
//! [`new`] takes the inbound handler callback (the prioritiser's request
//! handler) and returns the [`Behaviour`] to register with the swarm plus a
//! cloneable [`Sender`] that the prioritiser uses to drive exchanges.

mod behaviour;
mod handler;
pub(crate) mod protocol;

use std::sync::Arc;

use futures::future::BoxFuture;
use libp2p::PeerId;
use pluto_core::corepb::v1::priority::PriorityMsg;
use pluto_p2p::p2p_context::P2PContext;
use tokio::sync::{mpsc, oneshot};

pub use behaviour::{Behaviour, Event};
pub use handler::{FromBehaviour, Handler, InboundFailure, OutboundRequest};

use crate::error::Error;

/// Registered inbound request handler.
///
/// Invoked with the remote peer id and the received request. Returns the
/// response to send (`Some`), no response (`None`, closing the stream), or an
/// error (logged, stream closed).
pub type InboundHandler = Arc<
    dyn Fn(PeerId, PriorityMsg) -> BoxFuture<'static, crate::Result<Option<PriorityMsg>>>
        + Send
        + Sync
        + 'static,
>;

/// Command sent from a [`Sender`] to the [`Behaviour`].
pub(crate) enum Command {
    /// Send a request to a peer and resolve with its response.
    SendReceive {
        /// Target peer.
        peer: PeerId,
        /// Request payload and response channel.
        request: OutboundRequest,
    },
}

/// Cloneable handle used to initiate outbound priority exchanges.
#[derive(Clone)]
pub struct Sender {
    command_tx: mpsc::UnboundedSender<Command>,
}

impl Sender {
    /// Sends `request` to `peer` and resolves with the peer's response.
    ///
    /// Errors with [`Error::Shutdown`] if the behaviour has been dropped, and
    /// with [`Error::Transport`]/[`Error::Unsupported`] on dial or stream
    /// failure. The caller is responsible for applying an exchange timeout.
    pub fn send_receive(
        &self,
        peer: PeerId,
        request: PriorityMsg,
    ) -> BoxFuture<'static, crate::Result<PriorityMsg>> {
        let command_tx = self.command_tx.clone();
        Box::pin(async move {
            let (response_tx, response_rx) = oneshot::channel();
            command_tx
                .send(Command::SendReceive {
                    peer,
                    request: OutboundRequest {
                        request,
                        response: response_tx,
                    },
                })
                .map_err(|_| Error::Shutdown)?;

            response_rx.await.map_err(|_| Error::Shutdown)?
        })
    }
}

/// Creates the priority transport behaviour and an outbound [`Sender`].
///
/// `inbound_handler` is invoked for every received request on this protocol.
/// `p2p_context` is the shared node-wide context the behaviour reads for
/// known-peer gating and outbound dial-address resolution.
pub fn new(inbound_handler: InboundHandler, p2p_context: P2PContext) -> (Behaviour, Sender) {
    let (command_tx, command_rx) = mpsc::unbounded_channel();
    let behaviour = Behaviour::new(inbound_handler, command_rx, p2p_context);
    let sender = Sender { command_tx };
    (behaviour, sender)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::{FutureExt, StreamExt};
    use libp2p::{
        Multiaddr, Swarm,
        core::{Transport as _, transport::MemoryTransport, upgrade::Version},
        multiaddr::Protocol,
        swarm::SwarmEvent,
    };
    use pluto_core::corepb::v1::{core::Duty, priority::PriorityMsg};
    use pluto_p2p::{peer::peer_id_from_key, utils::keypair_from_secret_key};
    use pluto_testutil::random::generate_insecure_k1_key;
    use tokio::time::timeout;

    use super::*;

    fn priority_msg(peer_id: &str) -> PriorityMsg {
        PriorityMsg {
            duty: Some(Duty { slot: 1, r#type: 0 }),
            topics: Vec::new(),
            peer_id: peer_id.to_owned(),
            signature: Default::default(),
        }
    }

    /// In-process `/memory/<N>` address, where `N` is derived from the seed
    /// (non-zero so the kernel does not auto-assign a port).
    fn memory_addr(seed: u8) -> Multiaddr {
        Multiaddr::empty().with(Protocol::Memory(u64::from(seed) + 1))
    }

    struct TestNode {
        swarm: Swarm<Behaviour>,
        sender: Sender,
        addr: Multiaddr,
    }

    /// Builds a swarm over an in-process [`MemoryTransport`] whose priority
    /// behaviour responds to inbound requests with `responder(peer, request)`.
    /// The libp2p identity is derived from the same secp256k1 key used for the
    /// peer id, so the dialed peer id matches. `cluster` is the known-peer set
    /// the behaviour gates connections against (must include this node's peer
    /// and every peer it exchanges with).
    fn build_node<F>(seed: u8, cluster: Vec<PeerId>, responder: F) -> TestNode
    where
        F: Fn(PeerId, PriorityMsg) -> Option<PriorityMsg> + Send + Sync + 'static,
    {
        let key = generate_insecure_k1_key(seed);
        let keypair = keypair_from_secret_key(key).expect("keypair");

        let inbound: InboundHandler = Arc::new(move |peer, request| {
            let response = responder(peer, request);
            async move { Ok(response) }.boxed()
        });
        let (behaviour, sender) = new(inbound, P2PContext::new(cluster));

        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(|key| {
                MemoryTransport::default()
                    .upgrade(Version::V1)
                    .authenticate(libp2p::noise::Config::new(key).expect("noise config"))
                    .multiplex(libp2p::yamux::Config::default())
            })
            .expect("transport")
            .with_behaviour(|_key| behaviour)
            .expect("behaviour")
            .build();

        TestNode {
            swarm,
            sender,
            addr: memory_addr(seed),
        }
    }

    #[tokio::test]
    async fn send_receive_without_behaviour_returns_shutdown() {
        let (_behaviour, sender) = new(
            Arc::new(|_, _| async { Ok(None) }.boxed()),
            P2PContext::default(),
        );
        // Dropping the behaviour closes the command channel.
        drop(_behaviour);
        let peer = PeerId::random();
        let error = sender
            .send_receive(peer, priority_msg("x"))
            .await
            .expect_err("send should fail without a running behaviour");
        assert!(matches!(error, Error::Shutdown));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn round_trip_returns_peer_response() {
        let peer_a = peer_id_from_key(generate_insecure_k1_key(0).public_key()).expect("peer a id");
        let peer_b = peer_id_from_key(generate_insecure_k1_key(1).public_key()).expect("peer b id");

        let cluster = vec![peer_a, peer_b];

        // Node B echoes the request's peer id back inside its own response.
        let responder_peer_b = peer_b.to_string();
        let mut node_b = build_node(1, cluster.clone(), move |_peer, request| {
            Some(PriorityMsg {
                peer_id: responder_peer_b.clone(),
                ..request
            })
        });
        let mut node_a = build_node(0, cluster, |_peer, _request| Some(priority_msg("unused")));

        node_a
            .swarm
            .listen_on(node_a.addr.clone())
            .expect("listen a");
        node_b
            .swarm
            .listen_on(node_b.addr.clone())
            .expect("listen b");

        // Wait for both nodes to start listening.
        for swarm in [&mut node_a.swarm, &mut node_b.swarm] {
            loop {
                if matches!(
                    swarm.select_next_some().await,
                    SwarmEvent::NewListenAddr { .. }
                ) {
                    break;
                }
            }
        }

        node_a.swarm.dial(node_b.addr.clone()).expect("dial b");

        // Drive node B in the background while node A waits for the dialed
        // connection to establish. The behaviour only knows peer ids, not
        // addresses, so the outbound exchange must reuse an existing connection
        // rather than re-dialing by peer id (which has no known address).
        let sender_a = node_a.sender.clone();
        let mut swarm_a = node_a.swarm;
        let mut swarm_b = node_b.swarm;
        let driver_b = tokio::spawn(async move {
            loop {
                let _ = swarm_b.select_next_some().await;
            }
        });
        loop {
            if matches!(
                swarm_a.select_next_some().await,
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer_b
            ) {
                break;
            }
        }
        let driver_a = tokio::spawn(async move {
            loop {
                let _ = swarm_a.select_next_some().await;
            }
        });

        let request = priority_msg(&peer_a.to_string());
        let response = timeout(
            Duration::from_secs(10),
            sender_a.send_receive(peer_b, request),
        )
        .await
        .expect("exchange should complete")
        .expect("exchange should succeed");

        assert_eq!(response.peer_id, peer_b.to_string());
        assert_eq!(response.duty, Some(Duty { slot: 1, r#type: 0 }));

        driver_a.abort();
        driver_b.abort();
    }

    /// Concurrent exchanges to the same peer resolve each caller's oneshot with
    /// its own request's response, never by stream-negotiation order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_same_peer_exchanges_route_by_identity() {
        // Distinct seeds from the round-trip test so the in-process memory
        // addresses do not collide when tests run in parallel.
        let peer_a = peer_id_from_key(generate_insecure_k1_key(2).public_key()).expect("peer a id");
        let peer_b = peer_id_from_key(generate_insecure_k1_key(3).public_key()).expect("peer b id");
        let cluster = vec![peer_a, peer_b];

        // Node B echoes the request's duty (its slot distinguishes requests) and
        // stamps its own peer id on the response.
        let responder_peer_b = peer_b.to_string();
        let mut node_b = build_node(3, cluster.clone(), move |_peer, request| {
            Some(PriorityMsg {
                peer_id: responder_peer_b.clone(),
                duty: request.duty,
                ..request
            })
        });
        let mut node_a = build_node(2, cluster, |_peer, _request| Some(priority_msg("unused")));

        node_a
            .swarm
            .listen_on(node_a.addr.clone())
            .expect("listen a");
        node_b
            .swarm
            .listen_on(node_b.addr.clone())
            .expect("listen b");

        for swarm in [&mut node_a.swarm, &mut node_b.swarm] {
            loop {
                if matches!(
                    swarm.select_next_some().await,
                    SwarmEvent::NewListenAddr { .. }
                ) {
                    break;
                }
            }
        }

        node_a.swarm.dial(node_b.addr.clone()).expect("dial b");

        let sender_a = node_a.sender.clone();
        let mut swarm_a = node_a.swarm;
        let mut swarm_b = node_b.swarm;
        let driver_b = tokio::spawn(async move {
            loop {
                let _ = swarm_b.select_next_some().await;
            }
        });
        loop {
            if matches!(
                swarm_a.select_next_some().await,
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer_b
            ) {
                break;
            }
        }
        let driver_a = tokio::spawn(async move {
            loop {
                let _ = swarm_a.select_next_some().await;
            }
        });

        // Issue many concurrent exchanges to the same peer, each carrying a
        // distinct slot. Each response must echo the slot of its own request.
        let slots: Vec<u64> = (100..110).collect();
        let mut requests = Vec::new();
        for &slot in &slots {
            let req = PriorityMsg {
                duty: Some(Duty { slot, r#type: 0 }),
                ..priority_msg("x")
            };
            requests.push(sender_a.send_receive(peer_b, req));
        }

        let responses = timeout(Duration::from_secs(10), futures::future::join_all(requests))
            .await
            .expect("all exchanges complete");

        for (slot, response) in slots.iter().zip(responses) {
            let response = response.expect("exchange should succeed");
            assert_eq!(response.peer_id, peer_b.to_string());
            assert_eq!(
                response.duty.expect("duty echoed").slot,
                *slot,
                "response must match its own request slot"
            );
        }

        driver_a.abort();
        driver_b.abort();
    }

    /// `handle_pending_outbound_connection` offers the peer-store address for a
    /// known peer dialed by id, and nothing for an unknown peer or an
    /// address-based dial (no target id).
    #[test]
    fn pending_outbound_connection_resolves_known_peer_addresses() {
        use libp2p::{
            core::Endpoint,
            swarm::{ConnectionId, NetworkBehaviour},
        };

        let peer = peer_id_from_key(generate_insecure_k1_key(7).public_key()).expect("peer id");
        let addr = memory_addr(7);

        let ctx = P2PContext::new(vec![peer]);
        ctx.peer_store_write_lock()
            .set_peer_addresses(peer, vec![addr.clone()]);

        let (mut behaviour, _sender) = new(Arc::new(|_, _| async { Ok(None) }.boxed()), ctx);

        // Known peer with a stored address: that address is offered for the dial.
        let resolved = behaviour
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(1),
                Some(peer),
                &[],
                Endpoint::Dialer,
            )
            .expect("resolve known peer");
        assert_eq!(resolved, vec![addr]);

        // Unknown peer: no stored address, so the behaviour offers none (the
        // swarm/sibling behaviours must supply one).
        let unknown = peer_id_from_key(generate_insecure_k1_key(8).public_key()).expect("peer id");
        let none = behaviour
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(2),
                Some(unknown),
                &[],
                Endpoint::Dialer,
            )
            .expect("resolve unknown peer");
        assert!(none.is_empty(), "unknown peer must resolve to no address");

        // Address-based dial (no target peer id): nothing to resolve by id.
        let no_peer = behaviour
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(3),
                None,
                &[],
                Endpoint::Dialer,
            )
            .expect("resolve without peer id");
        assert!(
            no_peer.is_empty(),
            "address dial resolves no id-based address"
        );
    }

    /// A peer that is not in the responder's cluster set is served a no-op
    /// handler, so the priority protocol cannot be negotiated and the exchange
    /// fails with [`Error::Unsupported`].
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn exchange_with_non_cluster_peer_fails_negotiation() {
        let peer_a = peer_id_from_key(generate_insecure_k1_key(5).public_key()).expect("peer a id");
        let peer_b = peer_id_from_key(generate_insecure_k1_key(6).public_key()).expect("peer b id");

        // Node B does NOT know peer A, so B serves A a dummy handler and never
        // advertises the priority protocol on that connection.
        let mut node_b = build_node(6, vec![peer_b], |_peer, request| Some(request));
        // Node A knows B, so A's side installs a real handler and opens the
        // outbound exchange.
        let mut node_a = build_node(5, vec![peer_a, peer_b], |_peer, _request| {
            Some(priority_msg("unused"))
        });

        node_a
            .swarm
            .listen_on(node_a.addr.clone())
            .expect("listen a");
        node_b
            .swarm
            .listen_on(node_b.addr.clone())
            .expect("listen b");

        for swarm in [&mut node_a.swarm, &mut node_b.swarm] {
            loop {
                if matches!(
                    swarm.select_next_some().await,
                    SwarmEvent::NewListenAddr { .. }
                ) {
                    break;
                }
            }
        }

        node_a.swarm.dial(node_b.addr.clone()).expect("dial b");

        let sender_a = node_a.sender.clone();
        let mut swarm_a = node_a.swarm;
        let mut swarm_b = node_b.swarm;
        let driver_b = tokio::spawn(async move {
            loop {
                let _ = swarm_b.select_next_some().await;
            }
        });
        loop {
            if matches!(
                swarm_a.select_next_some().await,
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer_b
            ) {
                break;
            }
        }
        let driver_a = tokio::spawn(async move {
            loop {
                let _ = swarm_a.select_next_some().await;
            }
        });

        let error = timeout(
            Duration::from_secs(10),
            sender_a.send_receive(peer_b, priority_msg(&peer_a.to_string())),
        )
        .await
        .expect("exchange resolves")
        .expect_err("exchange must fail: B does not know A");
        assert!(
            matches!(error, Error::Unsupported),
            "expected negotiation failure, got {error:?}"
        );

        driver_a.abort();
        driver_b.abort();
    }

    /// The local send path is gated on the same cluster set as handler
    /// installation: a `send_receive` to a peer outside the context resolves to
    /// [`Error::Unsupported`] without dialing — crucially without routing a
    /// `Left` event to a `dummy` handler, which would abort the swarm task.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_receive_to_non_cluster_peer_is_unsupported() {
        let me = peer_id_from_key(generate_insecure_k1_key(9).public_key()).expect("peer id");
        // The context knows only this node; the target below is not a cluster
        // peer, so its connection (if any) would carry a dummy handler.
        let node = build_node(9, vec![me], |_peer, _request| Some(priority_msg("unused")));
        let sender = node.sender.clone();
        let mut swarm = node.swarm;
        let driver = tokio::spawn(async move {
            loop {
                let _ = swarm.select_next_some().await;
            }
        });

        let unknown = PeerId::random();
        let error = timeout(
            Duration::from_secs(5),
            sender.send_receive(unknown, priority_msg(&me.to_string())),
        )
        .await
        .expect("send resolves promptly")
        .expect_err("send to a non-cluster peer must fail");
        assert!(matches!(error, Error::Unsupported), "got {error:?}");

        driver.abort();
    }

    /// An inbound request that fails validation is surfaced to the application
    /// as `Event::InboundFailure` (previously such failures were silently
    /// dropped). A request with no `duty` is rejected by
    /// `check_required_fields` before the handler runs, yielding
    /// `InboundFailure::InvalidMessage`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn inbound_failure_surfaces_as_swarm_event() {
        let peer_a =
            peer_id_from_key(generate_insecure_k1_key(10).public_key()).expect("peer a id");
        let peer_b =
            peer_id_from_key(generate_insecure_k1_key(11).public_key()).expect("peer b id");
        let cluster = vec![peer_a, peer_b];

        let mut node_b = build_node(11, cluster.clone(), |_peer, request| Some(request));
        let mut node_a = build_node(10, cluster, |_peer, _request| Some(priority_msg("unused")));

        node_a
            .swarm
            .listen_on(node_a.addr.clone())
            .expect("listen a");
        node_b
            .swarm
            .listen_on(node_b.addr.clone())
            .expect("listen b");
        for swarm in [&mut node_a.swarm, &mut node_b.swarm] {
            loop {
                if matches!(
                    swarm.select_next_some().await,
                    SwarmEvent::NewListenAddr { .. }
                ) {
                    break;
                }
            }
        }

        node_a.swarm.dial(node_b.addr.clone()).expect("dial b");

        let sender_a = node_a.sender.clone();
        let mut swarm_a = node_a.swarm;
        let mut swarm_b = node_b.swarm;

        // Bring up both ends of the connection.
        let mut a_up = false;
        let mut b_up = false;
        while !(a_up && b_up) {
            tokio::select! {
                ev = swarm_a.select_next_some() => {
                    if matches!(ev, SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer_b) {
                        a_up = true;
                    }
                }
                ev = swarm_b.select_next_some() => {
                    if matches!(ev, SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer_a) {
                        b_up = true;
                    }
                }
            }
        }

        // Drive A in the background; its send fails when B closes without reply.
        let driver_a = tokio::spawn(async move {
            loop {
                let _ = swarm_a.select_next_some().await;
            }
        });
        // A request with no `duty` is rejected by B before the handler runs.
        let bad = PriorityMsg {
            duty: None,
            ..priority_msg(&peer_a.to_string())
        };
        let send = tokio::spawn(async move { sender_a.send_receive(peer_b, bad).await });

        let event = timeout(Duration::from_secs(10), async {
            loop {
                if let SwarmEvent::Behaviour(event) = swarm_b.select_next_some().await {
                    return event;
                }
            }
        })
        .await
        .expect("inbound failure surfaces within timeout");

        let Event::InboundFailure { peer, failure } = event;
        assert_eq!(peer, peer_a, "failure attributed to the sender");
        assert!(
            matches!(failure, InboundFailure::InvalidMessage),
            "got {failure:?}"
        );

        // The sender observes the closed stream as a transport error.
        let send_result = send.await.expect("send task joins");
        assert!(send_result.is_err(), "send of an invalid message must fail");

        driver_a.abort();
    }
}
