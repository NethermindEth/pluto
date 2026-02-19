//! EIP-2335 keystore management.
//!
//! This module provides functions to store and load private keys to/from
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335) compatible keystore files.
//! Passwords are expected/created in files with identical names as the
//! keystores, except with `.txt` extension.

mod error;
mod keystorev4;
mod load;
mod store;

pub use error::KeystoreError;
pub use load::{
    KeyFile, KeyFiles, extract_file_index, load_files_recursively, load_files_unordered,
};
pub use store::{
    CONFIRM_INSECURE_KEYS, ConfirmInsecure, Keystore, decrypt, encrypt, store_keys, store_keys_insecure,
};
