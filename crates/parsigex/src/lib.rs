//! Partial signature exchange protocol.

mod behaviour;
mod error;
mod handler;
mod protocol;

pub use behaviour::{
    Behaviour, Config, DutyGater, Event, Handle, ReceivedSub, ReceivedSubFuture, Verifier,
    received_subscriber,
};
pub use error::{Error, Failure, Result, VerifyError};
pub use handler::Handler;
pub use protocol::{decode_message, encode_message};

use libp2p::swarm::StreamProtocol;

/// The protocol name for partial signature exchange (version 2.0.0).
pub const PROTOCOL_NAME: StreamProtocol = StreamProtocol::new("/charon/parsigex/2.0.0");

/// Returns the supported protocols in precedence order.
pub fn protocols() -> Vec<StreamProtocol> {
    vec![PROTOCOL_NAME]
}
