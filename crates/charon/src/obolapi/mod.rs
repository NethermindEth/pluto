//! Obol API client for interacting with the Obol network API.

mod client;
mod error;
mod serde_helpers;
mod test_api;

pub mod exit;
pub mod publish;

pub use client::{Client, ClientOptions};
pub use error::{Error as ObolApiError, Result};
pub use exit::{
    ExitBlob, FullExitAuthBlob, FullExitResponse, PartialExitRequest, PartialExits,
    SignedVoluntaryExit, UnsignedPartialExitRequest,
};
pub use publish::RequestSignTermsAndConditions;
