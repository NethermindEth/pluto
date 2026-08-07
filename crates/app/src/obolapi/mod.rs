//! Obol API client for interacting with the Obol network API.

mod client;
mod error;
mod helper;
mod test;

pub mod exit;
pub mod feerecipient;
pub mod publish;

pub use client::{Client, ClientOptions};
pub use error::{Error as ObolApiError, Result};
pub use exit::{
    ExitBlob, FullExitAuthBlob, FullExitResponse, PartialExitRequest, PartialExits,
    SignedVoluntaryExit, UnsignedPartialExitRequest,
};
pub use feerecipient::{
    FeeRecipientBuilderRegistration, FeeRecipientFetchRequest, FeeRecipientFetchResponse,
    FeeRecipientPartialSig, FeeRecipientValidator, PartialFeeRecipientRequest, PartialRegistration,
};
pub use publish::RequestSignTermsAndConditions;
