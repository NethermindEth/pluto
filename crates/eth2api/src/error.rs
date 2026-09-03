//! Error type of [`EthBeaconNodeApiClient`](crate::EthBeaconNodeApiClient).

use crate::spec::phase0;

/// Error that can occur when using the
/// [`EthBeaconNodeApiClient`](crate::EthBeaconNodeApiClient).
#[derive(Debug, thiserror::Error)]
pub enum EthBeaconNodeApiClientError {
    /// Underlying error from the client when making a request.
    #[error("Request error: {0}")]
    RequestError(#[from] anyhow::Error),

    /// Unexpected response, e.g, got an error when an Ok response was expected
    #[error("Unexpected response")]
    UnexpectedResponse,

    /// Unexpected type in response
    #[error("Unexpected type in response")]
    UnexpectedType,

    /// Failed to parse a response field.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Zero slot duration or slots per epoch in network spec
    #[error("Zero slot duration or slots per epoch in network spec")]
    ZeroSlotDurationOrSlotsPerEpoch,

    /// A duty was returned for a slot outside the epoch it was requested for.
    #[error("Received duty for slot {slot} outside of requested epoch {epoch}")]
    DutySlotOutsideEpoch {
        /// Slot the beacon node reported the duty for.
        slot: phase0::Slot,
        /// Epoch the duties were requested for.
        epoch: phase0::Epoch,
    },

    /// Error while opening the beacon node SSE event stream (request send or
    /// non-success status).
    #[error("Event stream request error: {0}")]
    EventStreamRequest(#[from] reqwest::Error),

    /// Error while reading from the beacon node SSE event stream.
    #[error("Event stream read error: {0}")]
    EventStreamRead(#[from] eventsource_stream::EventStreamError<reqwest::Error>),
}
