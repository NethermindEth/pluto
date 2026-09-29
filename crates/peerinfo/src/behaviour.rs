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
    /// Creates a new [`Behaviour`] with the given `local_peer_id` and
    /// configuration.
    pub fn new(local_peer_id: PeerId, config: Config) -> Self {
        let name = pluto_p2p::name::peer_name(&local_peer_id);

        PEERINFO_METRICS.version
            [&PeerVersionLabels::new(&name, &config.local_info().pluto_version)]
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
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(self.config.clone(), peer))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(self.config.clone(), peer))
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
    use std::time::Duration;

    use futures::StreamExt;
    use libp2p::{
        Multiaddr, Swarm,
        core::{Transport as _, transport::MemoryTransport, upgrade::Version},
        multiaddr::Protocol,
        swarm::SwarmEvent,
    };
    use pluto_p2p::utils::keypair_from_secret_key;
    use pluto_testutil::random::generate_insecure_k1_key;
    use tokio::time::timeout;

    use super::*;
    use crate::config::LocalPeerInfo;

    /// In-process `/memory/<N>` address, where `N` is derived from the seed
    /// (non-zero so the kernel does not auto-assign a port).
    fn memory_addr(seed: u8) -> Multiaddr {
        Multiaddr::empty().with(Protocol::Memory(u64::from(seed) + 1))
    }

    /// Builds a swarm over an in-process [`MemoryTransport`] running the
    /// peerinfo [`Behaviour`], with a short exchange interval so the test
    /// does not have to wait out the (60s default) real-world cadence.
    fn build_swarm(seed: u8, local_info: LocalPeerInfo) -> Swarm<Behaviour> {
        let key = generate_insecure_k1_key(seed);
        let keypair = keypair_from_secret_key(key).expect("keypair");
        let peer_id = keypair.public().to_peer_id();
        let config = Config::new(local_info).with_interval(Duration::from_millis(5));

        // Matches `pluto_p2p::p2p::yamux_config`: this call also switches
        // the backend to the same (legacy) yamux version production uses.
        let mut yamux_config = libp2p::yamux::Config::default();
        yamux_config.set_max_num_streams(2_048);

        libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(|key| {
                MemoryTransport::default()
                    .upgrade(Version::V1)
                    .authenticate(libp2p::noise::Config::new(key).expect("noise config"))
                    .multiplex(yamux_config)
            })
            .expect("transport")
            .with_behaviour(|_key| Behaviour::new(peer_id, config))
            .expect("behaviour")
            .build()
    }

    /// End-to-end coverage that a peerinfo exchange completes over a
    /// gracefully-closed stream (see #711).
    ///
    /// Exercises a real inbound `recv_peer_info` / outbound `send_peer_info`
    /// exchange between two swarms and asserts the response arrives intact.
    ///
    /// Note: `MemoryTransport` doesn't reproduce the kernel-level race the
    /// fix addresses — verified empirically by reverting the `close_stream`
    /// calls, which still passed this test 30/30 runs — so it guards
    /// against truncation/hangs/garbled responses, not the reset itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn inbound_response_is_fully_readable_by_remote() {
        let info_a = LocalPeerInfo::new("v1.7.1", vec![0u8; 32], "0000000", false, "node-a");
        let info_b = LocalPeerInfo::new("v1.7.1", vec![0xABu8; 32], "abc1234", true, "node-b");

        let mut swarm_a = build_swarm(40, info_a);
        let mut swarm_b = build_swarm(41, info_b);

        let addr_b = memory_addr(41);
        swarm_b.listen_on(addr_b.clone()).expect("listen b");
        loop {
            if matches!(
                swarm_b.select_next_some().await,
                SwarmEvent::NewListenAddr { .. }
            ) {
                break;
            }
        }

        // Drive node B in the background: it answers A's inbound peerinfo
        // request via `recv_peer_info`, which now closes the stream
        // gracefully instead of dropping it.
        let driver_b = tokio::spawn(async move {
            loop {
                let _ = swarm_b.select_next_some().await;
            }
        });

        swarm_a.dial(addr_b).expect("dial b");

        // Poll node A until its outbound exchange with B completes
        // (`send_peer_info` read B's response after B wrote and closed).
        let received = timeout(Duration::from_secs(10), async {
            loop {
                if let SwarmEvent::Behaviour(Event::Received { info, .. }) =
                    swarm_a.select_next_some().await
                {
                    return info;
                }
            }
        })
        .await
        .expect("peerinfo exchange should complete");

        assert_eq!(received.nickname, "node-b");
        assert_eq!(received.pluto_version, "v1.7.1");
        assert_eq!(received.git_hash, "abc1234");
        assert!(received.builder_api_enabled);
        assert_eq!(received.lock_hash.to_vec(), vec![0xABu8; 32]);

        driver_b.abort();
    }
}
