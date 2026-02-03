//! Connection handler for the gater behaviour.
//!
//! This is a dummy handler since the gater doesn't need to negotiate any
//! protocols or handle any connection-level events. The actual gating logic
//! happens at the connection establishment phase in the `NetworkBehaviour`
//! implementation.

use std::{
    convert::Infallible,
    task::{Context, Poll},
};

use libp2p::swarm::{
    ConnectionHandler, ConnectionHandlerEvent, Stream, SubstreamProtocol, handler::ConnectionEvent,
};

/// Dummy connection handler for the gater.
///
/// This handler doesn't negotiate any protocols or handle any events.
/// It exists only to satisfy the `NetworkBehaviour` trait requirements.
#[derive(Debug, Clone, Default)]
pub struct Handler;

impl ConnectionHandler for Handler {
    type FromBehaviour = Infallible;
    type InboundOpenInfo = ();
    type InboundProtocol = DeniedUpgrade;
    type OutboundOpenInfo = Infallible;
    type OutboundProtocol = DeniedUpgrade;
    type ToBehaviour = Infallible;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(DeniedUpgrade, ())
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        Poll::Pending
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {}
    }

    fn on_connection_event(
        &mut self,
        _event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        // No events to handle
    }
}

/// A protocol upgrade that always denies the upgrade.
///
/// This is used because the gater doesn't need to negotiate any protocols.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeniedUpgrade;

impl libp2p::core::UpgradeInfo for DeniedUpgrade {
    type Info = &'static str;
    type InfoIter = std::iter::Empty<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::empty()
    }
}

impl libp2p::core::upgrade::InboundUpgrade<Stream> for DeniedUpgrade {
    type Error = Infallible;
    type Future = std::future::Pending<Result<Self::Output, Self::Error>>;
    type Output = Infallible;

    fn upgrade_inbound(self, _: Stream, _: Self::Info) -> Self::Future {
        std::future::pending()
    }
}

impl libp2p::core::upgrade::OutboundUpgrade<Stream> for DeniedUpgrade {
    type Error = Infallible;
    type Future = std::future::Pending<Result<Self::Output, Self::Error>>;
    type Output = Infallible;

    fn upgrade_outbound(self, _: Stream, _: Self::Info) -> Self::Future {
        std::future::pending()
    }
}
