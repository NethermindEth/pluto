//! Optional behaviour wrapper.
//!
//! This module provides a wrapper for optionally enabling a network behaviour.

use std::task::{Context, Poll};

use either::Either;
use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm, dummy,
    },
};

/// A wrapper for an optional network behaviour.
///
/// This struct allows a behaviour to be optionally present. When the inner
/// behaviour is `None`, all `NetworkBehaviour` methods become no-ops.
#[derive(Debug, Default, Clone)]
pub struct OptionalBehaviour<B> {
    inner: Option<B>,
}

impl<B> OptionalBehaviour<B> {
    /// Creates a new `OptionalBehaviour` with the given inner behaviour.
    pub fn new(behaviour: B) -> Self {
        Self {
            inner: Some(behaviour),
        }
    }

    /// Creates an empty `OptionalBehaviour` with no inner behaviour.
    pub fn none() -> Self {
        Self { inner: None }
    }

    /// Returns a reference to the inner behaviour, if present.
    pub fn as_ref(&self) -> Option<&B> {
        self.inner.as_ref()
    }

    /// Returns a mutable reference to the inner behaviour, if present.
    pub fn as_mut(&mut self) -> Option<&mut B> {
        self.inner.as_mut()
    }

    /// Returns `true` if the inner behaviour is present.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }
}

impl<B> From<Option<B>> for OptionalBehaviour<B> {
    fn from(inner: Option<B>) -> Self {
        Self { inner }
    }
}

impl<B> From<B> for OptionalBehaviour<B> {
    fn from(behaviour: B) -> Self {
        Self::new(behaviour)
    }
}

impl<B: NetworkBehaviour> NetworkBehaviour for OptionalBehaviour<B> {
    type ConnectionHandler = Either<THandler<B>, dummy::ConnectionHandler>;
    type ToSwarm = <B as NetworkBehaviour>::ToSwarm;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if let Some(inner) = self.inner.as_mut() {
            inner.handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
        } else {
            Ok(())
        }
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: libp2p::core::Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if let Some(inner) = self.inner.as_mut() {
            inner.handle_pending_outbound_connection(
                connection_id,
                maybe_peer,
                addresses,
                effective_role,
            )
        } else {
            Ok(vec![])
        }
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if let Some(inner) = self.inner.as_mut() {
            let res = inner
                .handle_established_inbound_connection(connection_id, peer, local_addr, remote_addr)
                .map(Either::Left)?;
            Ok(res)
        } else {
            Ok(Either::Right(dummy::ConnectionHandler))
        }
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: libp2p::core::Endpoint,
        port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if let Some(inner) = self.inner.as_mut() {
            let res = inner
                .handle_established_outbound_connection(
                    connection_id,
                    peer,
                    addr,
                    role_override,
                    port_use,
                )
                .map(Either::Left)?;
            Ok(res)
        } else {
            Ok(Either::Right(dummy::ConnectionHandler))
        }
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let Some(inner) = self.inner.as_mut() {
            inner.on_swarm_event(event);
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        if let Some(inner) = self.inner.as_mut() {
            let right = event.left().expect("inner is Some");
            inner.on_connection_handler_event(peer_id, connection_id, right);
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(inner) = self.inner.as_mut() {
            inner.poll(cx).map(|event| event.map_in(Either::Left))
        } else {
            Poll::Pending
        }
    }
}
