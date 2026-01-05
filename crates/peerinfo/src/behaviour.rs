//! NetworkBehaviour implementation for the peerinfo protocol.
//!
//! This behaviour manages peer info exchanges across all connections,
//! emitting events when peer info is received from remote peers.

use std::{
    collections::VecDeque,
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
    },
};

use crate::{
    Failure,
    config::Config,
    handler::{Handler, Success},
    metrics::{PEERINFO_METRICS, PeerGitHashLabels, PeerNicknameLabels, PeerVersionLabels},
    peerinfopb::v1::peerinfo::PeerInfo,
};

/// Event emitted by the peerinfo behaviour.
#[derive(Debug, Clone)]
pub enum Event {
    /// Received peer info from a remote peer.
    Received {
        /// The peer that sent the info.
        peer: PeerId,
        /// The connection on which the info was received.
        connection: ConnectionId,
        /// The peer info received.
        info: PeerInfo,
    },
    /// A peer info exchange failed.
    Error {
        /// The peer with which the exchange failed.
        peer: PeerId,
        /// The connection on which the exchange failed.
        connection: ConnectionId,
        /// The failure reason.
        error: Failure,
    },
}

/// Behaviour for the peerinfo protocol.
///
/// This behaviour periodically exchanges peer info with connected peers
/// and emits events when peer info is received.
pub struct Behaviour {
    /// Configuration for the behaviour.
    config: Config,
    /// Pending events to be emitted.
    events: VecDeque<Event>,
}

impl Behaviour {
    /// Creates a new [`Behaviour`] with the given configuration.
    pub fn new(config: Config) -> Self {
        let name = config.local_info().nickname.clone();

        PEERINFO_METRICS.version
            [&PeerVersionLabels::new(&name, &config.local_info().charon_version)]
            .set(1);
        PEERINFO_METRICS.git_commit[&PeerGitHashLabels::new(&name, &config.local_info().git_hash)]
            .set(1);
        PEERINFO_METRICS.nickname[&PeerNicknameLabels::new(&name, &config.local_info().nickname)]
            .set(1);

        let started_at = if let Some(started_at) = config.local_info().started_at {
            started_at.seconds
        } else {
            chrono::Utc::now().timestamp()
        };

        let started_at = started_at as f64;

        PEERINFO_METRICS.start_time_secs[&name].set(started_at);

        if config.local_info().builder_api_enabled {
            PEERINFO_METRICS.builder_api_enabled[&name].set(1);
        } else {
            PEERINFO_METRICS.builder_api_enabled[&name].set(0);
        }

        Self {
            config,
            events: VecDeque::new(),
        }
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(self.config.clone()))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(self.config.clone()))
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {
        // No special handling needed for swarm events
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            Ok(Success { peer_info }) => {
                self.events.push_back(Event::Received {
                    peer: peer_id,
                    connection: connection_id,
                    info: peer_info,
                });
            }
            Err(failure) => {
                self.events.push_back(Event::Error {
                    peer: peer_id,
                    connection: connection_id,
                    error: failure,
                });
            }
        }
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }

        Poll::Pending
    }
}
