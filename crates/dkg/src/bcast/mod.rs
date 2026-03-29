use std::time::Duration;

use libp2p::swarm::StreamProtocol;

mod behaviour;
mod component;
mod error;
pub mod handler;
mod protocol;

pub use behaviour::{Behaviour, Event};
pub use component::{CallbackFn, CheckFn, Component};
pub use error::{Error, Failure, Result};

/// The request-response protocol used to gather peer signatures.
pub const SIG_PROTOCOL_NAME: StreamProtocol = StreamProtocol::new("/charon/dkg/bcast/1.0.0/sig");

/// The fire-and-forget protocol used to fan out the fully signed message.
pub const MSG_PROTOCOL_NAME: StreamProtocol = StreamProtocol::new("/charon/dkg/bcast/1.0.0/msg");

/// The inbound handling timeout.
pub const RECEIVE_TIMEOUT: Duration = Duration::from_secs(60);

/// The outbound send timeout.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(62);
