//! # Charon Peerinfo
//!
//! The peerinfo protocol enables Charon nodes to exchange metadata about
//! themselves with connected peers. This includes version information,
//! cluster lock hash, git commit, builder API status, and nicknames.
//!
//! ## Protocol Overview
//!
//! The protocol works as a request-response pattern:
//! 1. Each peer periodically sends its own `PeerInfo` to connected peers
//! 2. The receiving peer responds with its own `PeerInfo`
//! 3. Both peers can use this information to verify compatibility and track
//!    peer metadata
//!
//! ## Usage
//!
//! ```rust,ignore
//! use charon_peerinfo::{Behaviour, Config, LocalPeerInfo};
//!
//! let local_info = LocalPeerInfo::new(
//!     "v1.0.0",
//!     vec![0u8; 32], // lock hash
//!     "abc1234",     // git hash
//!     false,         // builder API enabled
//!     "my-node",     // nickname
//! );
//!
//! let config = Config::new(local_info)
//!     .with_interval(Duration::from_secs(60))
//!     .with_timeout(Duration::from_secs(20));
//!
//! let behaviour = Behaviour::new(config);
//! ```

use libp2p::swarm::StreamProtocol;

/// Behaviour implementation for the peerinfo protocol.
pub mod behaviour;

/// Configuration for the peerinfo protocol.
pub mod config;

/// Failure types for the peerinfo protocol.
pub mod failure;

/// Connection handler for the peerinfo protocol.
pub mod handler;

/// Peerinfo protobuf definitions.
pub mod peerinfopb;

/// Wire protocol implementation.
pub mod protocol;

// Re-exports for convenience
pub use behaviour::{Behaviour, Event};
pub use config::{Config, LocalPeerInfo};
pub use failure::Failure;
pub use handler::Success;

/// The protocol name for the peerinfo protocol (version 2.0.0).
pub const PROTOCOL_NAME: StreamProtocol = StreamProtocol::new("/charon/peerinfo/2.0.0");

/// Returns the supported protocols of this package in order of precedence.
pub fn protocols() -> Vec<StreamProtocol> {
    vec![PROTOCOL_NAME]
}
