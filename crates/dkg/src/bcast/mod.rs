//! DKG reliable-broadcast protocol.
//!
//! Reliable broadcast lets one peer send a typed protobuf message to every
//! peer with signatures from the full DKG peer set. It first gathers one K1
//! signature per peer over `sha256(type_url || value)`, verifies the complete
//! signature set, then fans out the fully signed message. Receivers validate
//! the signatures before dispatching the typed callback registered for that
//! message ID.
//!
//! The protocol has four moving parts:
//! - [`Component`] is the caller-facing handle. It owns the message registry
//!   and submits outbound broadcasts to the swarm-owned [`Behaviour`].
//! - [`Behaviour`] coordinates one active outbound broadcast at a time. It asks
//!   peers for signatures, verifies the signature set, sends the final signed
//!   message, and emits [`Event`] terminal status.
//! - [`handler::Handler`] owns per-connection streams. It serves inbound
//!   signature requests and fully signed messages, and reports outbound stream
//!   results back to [`Behaviour`].
//! - The typed registry maps logical message IDs to protocol-specific
//!   validation and callback functions.
//!
//! High-level outbound flow:
//!
//! ```text
//! caller
//!   |
//!   | Component::broadcast(...) or Component::broadcast_and_wait(...)
//!   v
//! Behaviour command queue
//!   |
//!   | sign local message hash
//!   | request peer signatures over /sig
//!   v
//! Handler per peer
//!   |
//!   | collect signatures
//!   | verify full signature set
//!   | send signed message over /msg
//!   v
//! BroadcastCompleted / BroadcastFailed
//! ```
//!
//! Inbound signature path:
//! - A remote peer opens [`SIG_PROTOCOL_NAME`] and sends a signature request.
//! - [`handler::Handler`] checks the dedup key `(peer_id, msg_id)` before
//!   signing, so one peer cannot make this node sign conflicting hashes for the
//!   same message ID.
//! - The registered `check` function validates the typed message before this
//!   node signs it.
//! - The handler returns this node's K1 signature for the wrapped message.
//!
//! Inbound message path:
//! - A remote peer opens [`MSG_PROTOCOL_NAME`] and sends the fully signed
//!   broadcast message.
//! - [`handler::Handler`] verifies the signature count, ordering, and K1
//!   signatures against the configured peer list.
//! - The registered typed callback receives the decoded message and can update
//!   protocol state.
//!
//! API choice:
//! - [`Component::broadcast`] only enqueues the broadcast. Use it when the
//!   caller observes [`Event`] separately or intentionally does not need to
//!   wait for terminal status.
//! - [`Component::broadcast_and_wait`] enqueues and waits for terminal status.
//!   Use it when the next protocol step depends on terminal send status.
//!
//! Keep the ownership boundary clear: [`Component`] is a lightweight handle,
//! [`Behaviour`] owns swarm-level progress, and [`handler::Handler`] owns live
//! streams for one connection.

use std::time::Duration;

use libp2p::swarm::StreamProtocol;

mod behaviour;
mod component;
mod error;
pub mod handler;
mod protocol;

pub use behaviour::{Behaviour, Event};
pub use component::{CallbackFn, CheckFn, Component};
pub use error::{Error, Failure, Result, SenderPeerMismatch};

/// The request-response protocol used to gather peer signatures.
pub const SIG_PROTOCOL_NAME: StreamProtocol = StreamProtocol::new("/charon/dkg/bcast/1.0.0/sig");

/// The fire-and-forget protocol used to fan out the fully signed message.
pub const MSG_PROTOCOL_NAME: StreamProtocol = StreamProtocol::new("/charon/dkg/bcast/1.0.0/msg");

/// The inbound handling timeout.
pub const RECEIVE_TIMEOUT: Duration = Duration::from_secs(60);

/// The outbound send timeout.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(62);
