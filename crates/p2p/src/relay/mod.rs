//! Relay reservation and cluster-peer routing.
//!
//! [`RelayManager`] is a libp2p [`NetworkBehaviour`] with three
//! responsibilities:
//!
//! 1. Subscribe to [`MutablePeer`] watch channels to receive relay address
//!    updates as they're discovered.
//! 2. Manage each relay's reservation lifecycle (`Dialing → Established →
//!    Reserved`) and redial with exponential backoff when transport connections
//!    drop.
//! 3. Route known cluster peers through reserved relay circuits so peer-to-peer
//!    traffic can traverse NATs that would otherwise block direct dials.
//!
//! The implementation is split into focused submodules:
//!
//! - `event` — public event/error types ([`RelayManagerEvent`],
//!   [`RelayDialError`], [`RelayDialType`]).
//! - `dial` — dial-campaign machinery: exponential backoff and the per-target
//!   dial state stream.
//! - `manager` — the [`RelayManager`] behaviour, its [`RelayConnectionState`]
//!   lifecycle, and the [`NetworkBehaviour`] implementation.
//!
//! [`RelayManager`]: crate::relay::RelayManager
//! [`RelayConnectionState`]: crate::relay::RelayConnectionState
//! [`RelayManagerEvent`]: crate::relay::RelayManagerEvent
//! [`RelayDialError`]: crate::relay::RelayDialError
//! [`RelayDialType`]: crate::relay::RelayDialType
//! [`NetworkBehaviour`]: libp2p::swarm::NetworkBehaviour
//! [`MutablePeer`]: crate::peer::MutablePeer

mod dial;
mod event;
mod manager;

pub use event::{RelayDialError, RelayDialType, RelayManagerEvent};
pub use manager::{RelayConnectionState, RelayManager};
