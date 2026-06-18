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
use tokio::sync::{mpsc, oneshot};

pub use behaviour::{Behaviour, Event};
pub use handler::{FromBehaviour, Handler, OutboundRequest};

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
pub fn new(inbound_handler: InboundHandler) -> (Behaviour, Sender) {
    let (command_tx, command_rx) = mpsc::unbounded_channel();
    let behaviour = Behaviour::new(inbound_handler, command_rx);
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
    /// peer id, so the dialed peer id matches.
    fn build_node<F>(seed: u8, responder: F) -> TestNode
    where
        F: Fn(PeerId, PriorityMsg) -> Option<PriorityMsg> + Send + Sync + 'static,
    {
        let key = generate_insecure_k1_key(seed);
        let keypair = keypair_from_secret_key(key).expect("keypair");

        let inbound: InboundHandler = Arc::new(move |peer, request| {
            let response = responder(peer, request);
            async move { Ok(response) }.boxed()
        });
        let (behaviour, sender) = new(inbound);

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
        let (_behaviour, sender) = new(Arc::new(|_, _| async { Ok(None) }.boxed()));
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

        // Node B echoes the request's peer id back inside its own response.
        let responder_peer_b = peer_b.to_string();
        let mut node_b = build_node(1, move |_peer, request| {
            Some(PriorityMsg {
                peer_id: responder_peer_b.clone(),
                ..request
            })
        });
        let mut node_a = build_node(0, |_peer, _request| Some(priority_msg("unused")));

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
        let peer_b = peer_id_from_key(generate_insecure_k1_key(3).public_key()).expect("peer b id");

        // Node B echoes the request's duty (its slot distinguishes requests) and
        // stamps its own peer id on the response.
        let responder_peer_b = peer_b.to_string();
        let mut node_b = build_node(3, move |_peer, request| {
            Some(PriorityMsg {
                peer_id: responder_peer_b.clone(),
                duty: request.duty,
                ..request
            })
        });
        let mut node_a = build_node(2, |_peer, _request| Some(priority_msg("unused")));

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
}
