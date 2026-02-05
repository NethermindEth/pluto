/// Validate Beacon node versions
pub mod version;

/// Cache of Validators retrieved from the Beacon node
pub mod valcache;

/// Extensions module to the `Eth2Api` crate
///
/// Includes additional data types and functions to reduce the boilerplate when
/// interacting with `eth2api`.
pub mod eth2api;
