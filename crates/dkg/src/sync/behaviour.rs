use std::{
    collections::{HashMap, HashSet, VecDeque},
    task::{Context, Poll},
};

use either::Either;
use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm, dummy,
        dial_opts::{DialOpts, PeerCondition},
    },
};
use pluto_p2p::p2p_context::P2PContext;
use tokio::sync::mpsc;

use super::{Command, client::Client, handler::Handler, server::Server};

/// Event emitted by the sync behaviour.
#[derive(Debug, Clone)]
pub enum Event {}

/// Swarm behaviour backing the DKG sync protocol.
pub struct Behaviour {
    server: Server,
    clients: HashMap<PeerId, Client>,
    p2p_context: P2PContext,
    command_rx: mpsc::UnboundedReceiver<Command>,
    pending_dials: HashSet<PeerId>,
    pending_events: VecDeque<ToSwarm<Event, THandlerInEvent<Self>>>,
}

impl Behaviour {
    /// Creates a new sync behaviour from a server and client handles.
    pub(crate) fn new(
        server: Server,
        clients: impl IntoIterator<Item = Client>,
        p2p_context: P2PContext,
        command_rx: mpsc::UnboundedReceiver<Command>,
    ) -> Self {
        Self {
            server,
            clients: clients
                .into_iter()
                .map(|client| (client.peer_id(), client))
                .collect(),
            p2p_context,
            command_rx,
            pending_dials: HashSet::new(),
            pending_events: VecDeque::new(),
        }
    }

    fn new_handler(&self, peer: PeerId) -> Handler {
        Handler::new(peer, self.server.clone(), self.clients.get(&peer).cloned())
    }

    fn connection_handler_for_peer(&self, peer: PeerId) -> THandler<Self> {
        if self.clients.contains_key(&peer) {
            Either::Left(self.new_handler(peer))
        } else {
            Either::Right(dummy::ConnectionHandler)
        }
    }

    fn is_connected(&self, peer_id: &PeerId) -> bool {
        !self
            .p2p_context
            .peer_store_lock()
            .connections_to_peer(peer_id)
            .is_empty()
    }

    fn queue_dial(&mut self, peer_id: PeerId) {
        if self.is_connected(&peer_id) || !self.pending_dials.insert(peer_id) {
            return;
        }

        self.pending_events.push_back(ToSwarm::Dial {
            opts: DialOpts::peer_id(peer_id)
                .condition(PeerCondition::DisconnectedAndNotDialing)
                .build(),
        });
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::Activate(peer_id) => {
                let Some(client) = self.clients.get(&peer_id) else {
                    return;
                };

                if client.should_run() && !client.is_connected() {
                    self.queue_dial(peer_id);
                }
            }
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
            FromSwarm::ConnectionEstablished(event) => {
                self.pending_dials.remove(&event.peer_id);
            }
            FromSwarm::ConnectionClosed(event) => {
                if event.remaining_established > 0 {
                    return;
                }

                // TODO: Go retries sync client connections until reconnect is disabled.
                // Re-queue active clients here (and on DialFailure below) so peers that
                // restart before initial cluster sync can be dialed again.
                self.pending_dials.remove(&event.peer_id);

                if let Some(client) = self.clients.get(&event.peer_id) {
                    client.set_connected(false);
                    client.release_outbound();
                }
            }
            FromSwarm::DialFailure(event) => {
                if let Some(peer_id) = event.peer_id {
                    self.pending_dials.remove(&peer_id);
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
            Either::Left(event) => match event {},
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
            ConnectionClosed, ConnectionId, FromSwarm, NetworkBehaviour, ToSwarm,
            dial_opts::DialOpts,
        },
    };
    use pluto_core::version::SemVer;
    use tokio::sync::mpsc;

    use super::*;

    fn test_behaviour(client: Client) -> Behaviour {
        let (_unused_tx, command_rx) = mpsc::unbounded_channel();
        let version = SemVer::parse("v1.7").expect("valid version");
        let p2p_context = P2PContext::new([client.peer_id()]);
        Behaviour::new(
            Server::new(1, vec![1, 2, 3], version),
            [client],
            p2p_context,
            command_rx,
        )
    }

    #[test]
    fn active_client_requests_dial() {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let version = SemVer::parse("v1.7").expect("valid version");
        let peer_id = PeerId::random();
        let client = Client::new_wired(
            peer_id,
            vec![1, 2, 3],
            version.clone(),
            Default::default(),
            command_tx,
        );
        let server = Server::new(1, vec![1, 2, 3], version);
        let p2p_context = P2PContext::new([peer_id]);
        let mut behaviour = Behaviour::new(server, [client.clone()], p2p_context, command_rx);

        client.activate();

        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        let poll = NetworkBehaviour::poll(&mut behaviour, &mut cx);

        let Poll::Ready(ToSwarm::Dial { opts }) = poll else {
            panic!("expected dial event");
        };

        assert_eq!(DialOpts::get_peer_id(&opts), Some(peer_id));
    }

    #[test]
    fn connection_closed_keeps_client_state_until_last_connection() {
        let version = SemVer::parse("v1.7").expect("valid version");
        let peer_id = PeerId::random();
        let client = Client::new(peer_id, vec![1, 2, 3], version);
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
}
