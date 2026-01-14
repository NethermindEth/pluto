use std::collections::HashMap;

type Result<T> = std::result::Result<T, BeaconClientError>;

/// Defines errors that can occur when interacting with the Ethereum Beacon
/// client.
#[derive(Debug, thiserror::Error)]
pub enum BeaconClientError {}

/// TODO
pub struct BeaconClient;

/// TODO
pub type ValidatorIndex = u64;

/// TODO
pub struct Validator {}
