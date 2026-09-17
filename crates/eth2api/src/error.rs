//! Error type of [`EthBeaconNodeApiClient`](crate::EthBeaconNodeApiClient).

use crate::{
    HttpError,
    spec::{BuilderVersion, DataVersion, phase0},
};

/// Error that can occur when using the
/// [`EthBeaconNodeApiClient`](crate::EthBeaconNodeApiClient).
#[derive(Debug, thiserror::Error)]
pub enum EthBeaconNodeApiClientError {
    /// Sending the request, reading the response body or building the HTTP
    /// client failed.
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// The beacon node answered with a non-2xx status.
    #[error(transparent)]
    Http(#[from] HttpError),

    /// A 2xx response body did not decode into the expected shape.
    #[error("decoding JSON response body: {0}")]
    Decode(#[from] serde_path_to_error::Error<serde_json::Error>),

    /// The base URL does not parse.
    #[error("parsing base url: {0}")]
    Url(#[from] url::ParseError),

    /// The base URL cannot have path segments appended.
    #[error("base URL cannot be a base")]
    UrlCannotBeABase,

    /// A payload handed to the client cannot be sent as requested.
    #[error("invalid payload: {0}")]
    Payload(#[from] PayloadError),

    /// The fork schedule endpoint returned no entries.
    #[error("empty fork schedule")]
    EmptyForkSchedule,

    /// The genesis time does not fit a timestamp.
    #[error("genesis time {0} is not a valid timestamp")]
    InvalidGenesisTime(u64),

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

    /// Error while reading from the beacon node SSE event stream.
    #[error("Event stream read error: {0}")]
    EventStreamRead(#[from] eventsource_stream::EventStreamError<reqwest::Error>),
}

/// A payload the client cannot submit as requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// The payload carries no known consensus version.
    #[error("unknown consensus version")]
    UnknownVersion,

    /// The payload list is empty.
    #[error("empty payload list")]
    Empty,

    /// The payloads of one submission carry different consensus versions.
    #[error("payloads carry different consensus versions")]
    MixedVersions,

    /// A payload's fork does not match the fork of its submission.
    #[error("{payload} payload in a {submission} submission")]
    WrongFork {
        /// Version the submission is sent as.
        submission: DataVersion,
        /// Version of the offending payload.
        payload: DataVersion,
    },

    /// A versioned attestation carries no attestation.
    #[error("attestation has no payload")]
    MissingAttestation,

    /// A single attestation submission needs the attester's validator index.
    #[error("attestation has no validator index")]
    MissingValidatorIndex,

    /// An Electra attestation has no committee bit set.
    #[error("attestation has no committee bit set")]
    NoCommitteeBit,

    /// A blinded proposal was handed to the unblinded publish endpoint.
    #[error("blinded proposal on the unblinded publish endpoint")]
    BlindedOnUnblindedEndpoint,

    /// A validator registration uses a builder API version the client does not
    /// send.
    #[error("unsupported builder registration version {0}")]
    UnsupportedBuilderVersion(BuilderVersion),
}
