//! NetworkBehaviour implementation for the peerinfo protocol.
//!
//! This behaviour manages peer info exchanges across all connections,
//! emitting events when peer info is received from remote peers.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
    },
};
use tokio::sync::Mutex;

use crate::{
    Failure,
    config::Config,
    handler::{Handler, Success},
    metrics::PEERINFO_METRICS,
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
    /// Node-wide peer name to nickname map, shared with every connection
    /// handler.
    ///
    /// Charon keeps one such map on the `PeerInfo` node instance, seeded with
    /// the LOCAL node's name and nickname. Holding it here rather than in each
    /// [`Handler`] keeps it alive across reconnects and lets the companion
    /// "Peer name to nickname mappings" log show the whole cluster.
    nicknames: Arc<Mutex<HashMap<String, String>>>,
}

impl Behaviour {
    /// Creates a new [`Behaviour`] with the given `local_peer_id` and
    /// configuration.
    pub fn new(local_peer_id: PeerId, config: Config) -> Self {
        let name = pluto_p2p::name::peer_name(&local_peer_id);

        PEERINFO_METRICS.set_peer_version(&name, &config.local_info().pluto_version);
        PEERINFO_METRICS.set_peer_git_commit(&name, &config.local_info().git_hash);
        PEERINFO_METRICS.set_peer_nickname(&name, &config.local_info().nickname);

        let started_at = if let Some(started_at) = config.local_info().started_at {
            started_at.seconds
        } else {
            chrono::Utc::now().timestamp()
        };

        PEERINFO_METRICS.start_time_secs[&name].set(started_at);

        if config.local_info().builder_api_enabled {
            PEERINFO_METRICS.builder_api_enabled[&name].set(1);
        } else {
            PEERINFO_METRICS.builder_api_enabled[&name].set(0);
        }

        for (idx, peer) in config.peers().iter().enumerate() {
            let peer_name = pluto_p2p::name::peer_name(peer);
            PEERINFO_METRICS.index[&peer_name].set(idx);
        }

        // Seed with the LOCAL node's name and nickname, exactly as Charon's
        // `newInternal` does. Seeding a REMOTE name with our own nickname would
        // publish `nickname{peer=<remote>,peer_nickname=<ours>}`.
        let nicknames = HashMap::from([(name, config.local_info().nickname.clone())]);

        Self {
            config,
            events: VecDeque::new(),
            nicknames: Arc::new(Mutex::new(nicknames)),
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
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(
            self.config.clone(),
            peer,
            Arc::clone(&self.nicknames),
        ))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(
            self.config.clone(),
            peer,
            Arc::clone(&self.nicknames),
        ))
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

#[cfg(test)]
mod tests {
    use libp2p::{
        core::{Endpoint, transport::PortUse},
        swarm::ConnectionId,
    };

    use super::*;
    use crate::config::LocalPeerInfo;

    fn behaviour(local: PeerId, nickname: &str) -> Behaviour {
        let local_info = LocalPeerInfo::new("v1.7.1", vec![0u8; 32], "abc1234", false, nickname);
        Behaviour::new(local, Config::new(local_info))
    }

    /// Charon's `newInternal` seeds the map with the LOCAL node's name; seeding
    /// a remote name with our own nickname is what published
    /// `nickname{peer=<remote>,peer_nickname=<ours>}`.
    #[tokio::test]
    async fn nicknames_seeded_with_local_name() {
        let local = PeerId::random();
        let behaviour = behaviour(local, "alpha");

        let nicknames = behaviour.nicknames.lock().await;
        assert_eq!(
            &*nicknames,
            &HashMap::from([(pluto_p2p::name::peer_name(&local), "alpha".to_owned())]),
        );
    }

    /// The map lives on the behaviour, so every connection — including a
    /// reconnect — sees the same nicknames rather than a freshly reseeded one.
    #[tokio::test]
    async fn handlers_share_the_behaviour_map() {
        let local = PeerId::random();
        let mut behaviour = behaviour(local, "alpha");
        let remote = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();

        let first = behaviour
            .handle_established_outbound_connection(
                ConnectionId::new_unchecked(0),
                remote,
                &addr,
                Endpoint::Dialer,
                PortUse::Reuse,
            )
            .unwrap();
        let second = behaviour
            .handle_established_inbound_connection(
                ConnectionId::new_unchecked(1),
                remote,
                &addr,
                &addr,
            )
            .unwrap();

        // A nickname learnt on one connection is visible on the other and on
        // the behaviour itself.
        first
            .nicknames()
            .lock()
            .await
            .insert("quiet-river".to_owned(), "bravo".to_owned());

        assert_eq!(
            second.nicknames().lock().await.get("quiet-river"),
            Some(&"bravo".to_owned()),
        );
        assert_eq!(
            behaviour.nicknames.lock().await.get("quiet-river"),
            Some(&"bravo".to_owned()),
        );
    }
}
