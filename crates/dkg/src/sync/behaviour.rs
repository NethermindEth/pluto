use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use either::Either;
use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, DialError, FromSwarm, NetworkBehaviour, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
        dial_opts::{DialOpts, PeerCondition},
        dummy,
    },
};
use tokio::sync::mpsc;
use tokio::time::Sleep;

use super::{Command, client::Client, handler::Handler, server::Server};

const NO_ADDRESSES_RETRY_DELAY: Duration = Duration::from_millis(250);

/// Event emitted by the sync behaviour.
#[derive(Debug, Clone)]
pub enum Event {
    /// A peer advanced to a new sync step.
    PeerStepUpdated {
        /// The peer whose step was updated.
        peer_id: PeerId,
        /// The updated step.
        step: i64,
    },
    /// A peer requested graceful shutdown through sync.
    PeerShutdownObserved {
        /// The peer that requested shutdown.
        peer_id: PeerId,
    },
    /// A peer sent a sync message that failed.
    SyncRejected {
        /// The peer whose sync message was rejected.
        peer_id: PeerId,
        /// The validation error.
        error: super::error::Error,
    },
    /// A peer responded to an outbound sync message.
    PeerRttObserved {
        /// The peer that responded.
        peer_id: PeerId,
        /// Round-trip time between sending the sync message and receiving the
        /// response.
        rtt: Duration,
    },
}

/// Swarm behaviour backing the DKG sync protocol.
pub struct Behaviour {
    server: Server,
    clients: HashMap<PeerId, Client>,
    command_rx: mpsc::UnboundedReceiver<Command>,
    pending_events: VecDeque<ToSwarm<Event, THandlerInEvent<Self>>>,
    no_addresses_retries: HashMap<PeerId, Pin<Box<Sleep>>>,
}

impl Behaviour {
    /// Creates a new sync behaviour from a server and client handles.
    pub(crate) fn new(
        server: Server,
        clients: impl IntoIterator<Item = Client>,
        command_rx: mpsc::UnboundedReceiver<Command>,
    ) -> Self {
        Self {
            server,
            clients: clients
                .into_iter()
                .map(|client| (client.peer_id(), client))
                .collect(),
            command_rx,
            pending_events: VecDeque::new(),
            no_addresses_retries: HashMap::new(),
        }
    }

    fn connection_handler_for_peer(&self, peer: PeerId) -> THandler<Self> {
        match self.clients.get(&peer) {
            Some(client) => Either::Left(Handler::new(
                peer,
                self.server.clone(),
                Some(client.clone()),
            )),
            None => Either::Right(dummy::ConnectionHandler),
        }
    }

    /// Queues a dial for an active sync client when no connection to the peer
    /// exists. Initial activation does not require reconnect to be enabled.
    fn schedule_dial_if_needed(&mut self, peer_id: PeerId) {
        let Some(client) = self.clients.get(&peer_id) else {
            return;
        };

        if !client.should_schedule_dial() {
            return;
        }

        self.pending_events.push_back(ToSwarm::Dial {
            opts: DialOpts::peer_id(peer_id)
                .condition(PeerCondition::DisconnectedAndNotDialing)
                .build(),
        });
    }

    /// Returns whether a failed dial should be retried for this peer.
    fn should_retry_dial(&self, peer_id: PeerId) -> bool {
        self.clients
            .get(&peer_id)
            .is_some_and(|client| client.should_reconnect() && client.should_schedule_dial())
    }

    /// Queues an immediate retry for dial failures that already had addresses.
    fn schedule_dial_retry_if_needed(&mut self, peer_id: PeerId) {
        if self.should_retry_dial(peer_id) {
            self.schedule_dial_if_needed(peer_id);
        }
    }

    /// Schedules a delayed retry when no peer address is known yet.
    fn schedule_no_addresses_retry_if_needed(&mut self, peer_id: PeerId) {
        if self.should_retry_dial(peer_id) {
            self.no_addresses_retries
                .entry(peer_id)
                .or_insert_with(|| Box::pin(tokio::time::sleep(NO_ADDRESSES_RETRY_DELAY)));
        }
    }

    /// Polls delayed no-address retry timers and queues ready dials.
    fn poll_no_addresses_retries(&mut self, cx: &mut Context<'_>) {
        let ready = self
            .no_addresses_retries
            .iter_mut()
            .filter_map(|(peer_id, delay)| delay.as_mut().poll(cx).is_ready().then_some(*peer_id))
            .collect::<Vec<_>>();

        for peer_id in ready {
            self.no_addresses_retries.remove(&peer_id);
            self.schedule_dial_retry_if_needed(peer_id);
        }
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::Activate(peer_id) => self.schedule_dial_if_needed(peer_id),
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Either<Handler, dummy::ConnectionHandler>;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        Ok(self.connection_handler_for_peer(peer))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        Ok(self.connection_handler_for_peer(peer))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionClosed(event) => {
                if event.remaining_established > 0 {
                    return;
                }

                if let Some(client) = self.clients.get(&event.peer_id) {
                    client.set_connected(false);
                    client.release_outbound();
                }
                let server = self.server.clone();
                let peer_id = event.peer_id;
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(async move {
                        server.clear_connected(peer_id).await;
                    });
                }
            }
            FromSwarm::DialFailure(event) => {
                if let Some(peer_id) = event.peer_id {
                    match event.error {
                        DialError::Transport(_) => self.schedule_dial_retry_if_needed(peer_id),
                        DialError::NoAddresses => {
                            // Peer addresses may appear shortly after relay
                            // reservation/routing; avoid a tight retry loop.
                            self.schedule_no_addresses_retry_if_needed(peer_id);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            Either::Left(event) => self.pending_events.push_back(ToSwarm::GenerateEvent(event)),
            Either::Right(unreachable) => match unreachable {},
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        while let Poll::Ready(Some(command)) = self.command_rx.poll_recv(cx) {
            self.handle_command(command);
        }

        self.poll_no_addresses_retries(cx);

        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::task::Context;

    use futures::task::noop_waker_ref;
    use libp2p::{
        core::{ConnectedPoint, Endpoint, transport::PortUse},
        swarm::{
            ConnectionClosed, ConnectionId, DialError, DialFailure, FromSwarm, NetworkBehaviour,
            ToSwarm, dial_opts::DialOpts,
        },
    };
    use pluto_core::version::SemVer;
    use tokio::{
        sync::mpsc,
        time::{Duration, timeout},
    };
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::sync::ClientConfig;

    fn test_behaviour_with_command_channel(
        client: Client,
        command_rx: mpsc::UnboundedReceiver<Command>,
    ) -> Behaviour {
        let version = SemVer::parse("v1.7").expect("valid version");
        Behaviour::new(Server::new(1, vec![1, 2, 3], version), [client], command_rx)
    }

    fn test_behaviour(client: Client) -> Behaviour {
        let (_unused_tx, command_rx) = mpsc::unbounded_channel();
        test_behaviour_with_command_channel(client, command_rx)
    }

    fn assert_next_dial(behaviour: &mut Behaviour, peer_id: PeerId, message: &str) {
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        let poll = NetworkBehaviour::poll(behaviour, &mut cx);

        let Poll::Ready(ToSwarm::Dial { opts }) = poll else {
            panic!("{message}");
        };
        assert_eq!(DialOpts::get_peer_id(&opts), Some(peer_id));
    }

    fn assert_pending(behaviour: &mut Behaviour, message: &str) {
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        assert!(
            NetworkBehaviour::poll(behaviour, &mut cx).is_pending(),
            "{message}"
        );
    }

    fn activate_and_assert_dial(behaviour: &mut Behaviour, client: &Client) {
        client.activate().expect("activate should succeed");
        assert_next_dial(behaviour, client.peer_id(), "expected dial event");
    }

    #[test]
    fn active_client_requests_dial() {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let peer_id = PeerId::random();
        let client = Client::new(
            peer_id,
            vec![1, 2, 3],
            SemVer::parse("v1.7").expect("valid version"),
            Default::default(),
            Some(command_tx),
        );
        let mut behaviour = test_behaviour_with_command_channel(client.clone(), command_rx);

        activate_and_assert_dial(&mut behaviour, &client);
    }

    #[test]
    fn connection_closed_keeps_client_state_until_last_connection() {
        let version = SemVer::parse("v1.7").expect("valid version");
        let peer_id = PeerId::random();
        let client = Client::new(
            peer_id,
            vec![1, 2, 3],
            version,
            ClientConfig::default(),
            None,
        );
        client.set_connected(true);
        assert!(client.try_claim_outbound());

        let mut behaviour = test_behaviour(client.clone());

        let address = "/ip4/127.0.0.1/tcp/9000".parse().expect("valid multiaddr");
        let endpoint = ConnectedPoint::Dialer {
            address,
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };

        behaviour.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id,
            connection_id: ConnectionId::new_unchecked(1),
            endpoint: &endpoint,
            cause: None,
            remaining_established: 1,
        }));

        assert!(client.is_connected());
        assert!(!client.try_claim_outbound());

        behaviour.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id,
            connection_id: ConnectionId::new_unchecked(2),
            endpoint: &endpoint,
            cause: None,
            remaining_established: 0,
        }));

        assert!(!client.is_connected());
        assert!(client.try_claim_outbound());
    }

    #[test]
    fn transport_dial_failure_retries_active_client() {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let peer_id = PeerId::random();
        let client = Client::new(
            peer_id,
            vec![1, 2, 3],
            SemVer::parse("v1.7").expect("valid version"),
            Default::default(),
            Some(command_tx),
        );
        let mut behaviour = test_behaviour_with_command_channel(client.clone(), command_rx);

        activate_and_assert_dial(&mut behaviour, &client);

        let address = "/ip4/127.0.0.1/tcp/9000".parse().expect("valid multiaddr");
        let error = DialError::Transport(vec![(
            address,
            libp2p::TransportError::Other(std::io::Error::other("dial failed")),
        )]);
        behaviour.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(peer_id),
            error: &error,
            connection_id: ConnectionId::new_unchecked(1),
        }));

        assert_next_dial(&mut behaviour, peer_id, "expected retry dial event");
    }

    #[tokio::test]
    async fn no_addresses_dial_failure_retries_active_client_after_delay() {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let peer_id = PeerId::random();
        let client = Client::new(
            peer_id,
            vec![1, 2, 3],
            SemVer::parse("v1.7").expect("valid version"),
            Default::default(),
            Some(command_tx),
        );
        let mut behaviour = test_behaviour_with_command_channel(client.clone(), command_rx);

        activate_and_assert_dial(&mut behaviour, &client);

        let error = DialError::NoAddresses;
        behaviour.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(peer_id),
            error: &error,
            connection_id: ConnectionId::new_unchecked(1),
        }));

        assert_pending(&mut behaviour, "NoAddresses retry should be delayed");
        tokio::time::sleep(NO_ADDRESSES_RETRY_DELAY + Duration::from_millis(10)).await;
        assert_next_dial(&mut behaviour, peer_id, "expected retry dial event");
    }

    #[tokio::test]
    async fn last_connection_closed_clears_server_connected_state() {
        let peer_id = PeerId::random();
        let client = Client::new(
            peer_id,
            vec![1, 2, 3],
            SemVer::parse("v1.7").expect("valid version"),
            ClientConfig::default(),
            None,
        );
        let mut behaviour = test_behaviour(client);
        behaviour.server.start();
        behaviour.server.set_connected(peer_id).await;

        timeout(
            Duration::from_millis(10),
            behaviour
                .server
                .await_all_connected(CancellationToken::new()),
        )
        .await
        .expect("server should initially be connected")
        .expect("connected barrier should succeed");

        let address = "/ip4/127.0.0.1/tcp/9000".parse().expect("valid multiaddr");
        let endpoint = ConnectedPoint::Dialer {
            address,
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };

        behaviour.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id,
            connection_id: ConnectionId::new_unchecked(1),
            endpoint: &endpoint,
            cause: None,
            remaining_established: 0,
        }));

        for _ in 0..10 {
            tokio::task::yield_now().await;
            if timeout(
                Duration::from_millis(1),
                behaviour
                    .server
                    .await_all_connected(CancellationToken::new()),
            )
            .await
            .is_err()
            {
                return;
            }
        }

        panic!("connection close did not clear server connected state");
    }
}
