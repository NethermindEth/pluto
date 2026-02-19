//! Conversions between crypto (tbls), core, and eth2 BLS types.
//!
//! This module is a port of the Go `tbls/tblsconv` package, providing
//! conversion functions between the raw BLS byte-array types in
//! [`crate::types`], the core workflow types in [`pluto_core::types`],
//! and the eth2 phase0 types in [`pluto_eth2api::spec::phase0`].

use pluto_core::types as core_types;
use pluto_eth2api::spec::phase0;

use crate::types::{self, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

/// Converts a core workflow [`core_types::Signature`] into a [`types::Signature`].
pub fn sig_from_core(sig: &core_types::Signature) -> types::Signature {
    *sig.as_ref()
}

/// Converts a [`types::Signature`] into a core workflow [`core_types::Signature`].
pub fn sig_to_core(sig: types::Signature) -> core_types::Signature {
    core_types::Signature::new(sig)
}

/// Converts a [`types::Signature`] into an eth2 phase0 [`phase0::BLSSignature`].
pub fn sig_to_eth2(sig: types::Signature) -> phase0::BLSSignature {
    sig
}

/// Converts a [`types::PublicKey`] into an eth2 phase0 [`phase0::BLSPubKey`].
pub fn pubkey_to_eth2(pk: types::PublicKey) -> phase0::BLSPubKey {
    pk
}

/// Returns a [`types::PrivateKey`] from the given byte slice.
///
/// Returns an error if the data isn't exactly [`PRIVATE_KEY_LENGTH`] bytes.
pub fn privkey_from_bytes(data: &[u8]) -> Result<types::PrivateKey, ConvError> {
    if data.len() != PRIVATE_KEY_LENGTH {
        return Err(ConvError::InvalidLength {
            expected: PRIVATE_KEY_LENGTH,
            got: data.len(),
        });
    }
    let mut key = [0u8; PRIVATE_KEY_LENGTH];
    key.copy_from_slice(data);
    Ok(key)
}

/// Returns a [`types::PublicKey`] from the given byte slice.
///
/// Returns an error if the data isn't exactly [`PUBLIC_KEY_LENGTH`] bytes.
pub fn pubkey_from_bytes(data: &[u8]) -> Result<types::PublicKey, ConvError> {
    if data.len() != PUBLIC_KEY_LENGTH {
        return Err(ConvError::InvalidLength {
            expected: PUBLIC_KEY_LENGTH,
            got: data.len(),
        });
    }
    let mut key = [0u8; PUBLIC_KEY_LENGTH];
    key.copy_from_slice(data);
    Ok(key)
}

/// Returns a [`types::PublicKey`] from a core [`core_types::PubKey`].
pub fn pubkey_from_core(pk: &core_types::PubKey) -> types::PublicKey {
    let bytes: &[u8] = pk.as_ref();
    let mut key = [0u8; PUBLIC_KEY_LENGTH];
    key.copy_from_slice(bytes);
    key
}

/// Returns a [`types::Signature`] from the given byte slice.
///
/// Returns an error if the data isn't exactly [`SIGNATURE_LENGTH`] bytes.
pub fn signature_from_bytes(data: &[u8]) -> Result<types::Signature, ConvError> {
    if data.len() != SIGNATURE_LENGTH {
        return Err(ConvError::InvalidLength {
            expected: SIGNATURE_LENGTH,
            got: data.len(),
        });
    }
    let mut sig = [0u8; SIGNATURE_LENGTH];
    sig.copy_from_slice(data);
    Ok(sig)
}

/// Conversion error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConvError {
    /// Data is not of the expected length.
    #[error("data is not of the correct length: expected {expected}, got {got}")]
    InvalidLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privkey_from_bytes() {
        // empty input
        assert_eq!(
            privkey_from_bytes(&[]),
            Err(ConvError::InvalidLength {
                expected: PRIVATE_KEY_LENGTH,
                got: 0
            })
        );

        // more data than expected
        assert_eq!(
            privkey_from_bytes(&vec![42u8; PRIVATE_KEY_LENGTH + 1]),
            Err(ConvError::InvalidLength {
                expected: PRIVATE_KEY_LENGTH,
                got: PRIVATE_KEY_LENGTH + 1
            })
        );

        // less data than expected
        assert_eq!(
            privkey_from_bytes(&vec![42u8; PRIVATE_KEY_LENGTH - 1]),
            Err(ConvError::InvalidLength {
                expected: PRIVATE_KEY_LENGTH,
                got: PRIVATE_KEY_LENGTH - 1
            })
        );

        // correct length
        let data = vec![42u8; PRIVATE_KEY_LENGTH];
        let key = privkey_from_bytes(&data).expect("should succeed");
        assert_eq!(key, [42u8; PRIVATE_KEY_LENGTH]);
    }

    #[test]
    fn test_pubkey_from_bytes() {
        // empty input
        assert_eq!(
            pubkey_from_bytes(&[]),
            Err(ConvError::InvalidLength {
                expected: PUBLIC_KEY_LENGTH,
                got: 0
            })
        );

        // more data than expected
        assert_eq!(
            pubkey_from_bytes(&vec![42u8; PUBLIC_KEY_LENGTH + 1]),
            Err(ConvError::InvalidLength {
                expected: PUBLIC_KEY_LENGTH,
                got: PUBLIC_KEY_LENGTH + 1
            })
        );

        // less data than expected
        assert_eq!(
            pubkey_from_bytes(&vec![42u8; PUBLIC_KEY_LENGTH - 1]),
            Err(ConvError::InvalidLength {
                expected: PUBLIC_KEY_LENGTH,
                got: PUBLIC_KEY_LENGTH - 1
            })
        );

        // correct length
        let data = vec![42u8; PUBLIC_KEY_LENGTH];
        let key = pubkey_from_bytes(&data).expect("should succeed");
        assert_eq!(key, [42u8; PUBLIC_KEY_LENGTH]);
    }

    #[test]
    fn test_pubkey_to_eth2() {
        let data = vec![42u8; PUBLIC_KEY_LENGTH];
        let pubkey = pubkey_from_bytes(&data).expect("should succeed");
        let res = pubkey_to_eth2(pubkey);
        assert_eq!(pubkey[..], res[..]);
    }

    #[test]
    fn test_pubkey_from_core() {
        let bytes = [42u8; PUBLIC_KEY_LENGTH];
        let core_pk = core_types::PubKey::new(bytes);
        let res = pubkey_from_core(&core_pk);
        assert_eq!(res, bytes);
    }

    #[test]
    fn test_signature_from_bytes() {
        // empty input
        assert_eq!(
            signature_from_bytes(&[]),
            Err(ConvError::InvalidLength {
                expected: SIGNATURE_LENGTH,
                got: 0
            })
        );

        // more data than expected
        assert_eq!(
            signature_from_bytes(&vec![42u8; SIGNATURE_LENGTH + 1]),
            Err(ConvError::InvalidLength {
                expected: SIGNATURE_LENGTH,
                got: SIGNATURE_LENGTH + 1
            })
        );

        // less data than expected
        assert_eq!(
            signature_from_bytes(&vec![42u8; SIGNATURE_LENGTH - 1]),
            Err(ConvError::InvalidLength {
                expected: SIGNATURE_LENGTH,
                got: SIGNATURE_LENGTH - 1
            })
        );

        // correct length
        let data = vec![42u8; SIGNATURE_LENGTH];
        let sig = signature_from_bytes(&data).expect("should succeed");
        assert_eq!(sig, [42u8; SIGNATURE_LENGTH]);
    }

    #[test]
    fn test_sig_from_core() {
        let data = [42u8; SIGNATURE_LENGTH];
        let core_sig = core_types::Signature::new(data);
        let res = sig_from_core(&core_sig);
        assert_eq!(res, data);
    }

    #[test]
    fn test_sig_to_core() {
        let data = [42u8; SIGNATURE_LENGTH];
        let core_sig = sig_to_core(data);
        let bytes: &[u8] = core_sig.as_ref();
        assert_eq!(bytes, &data[..]);
    }

    #[test]
    fn test_sig_to_eth2() {
        let data = vec![42u8; SIGNATURE_LENGTH];
        let sig = signature_from_bytes(&data).expect("should succeed");
        let eth2_sig = sig_to_eth2(sig);
        assert_eq!(sig[..], eth2_sig[..]);
    }
}
