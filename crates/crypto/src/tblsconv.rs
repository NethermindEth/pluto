//! Conversions between crypto (tbls) and eth2 BLS types.
//!
//! Core-type conversion helpers are intentionally excluded here to avoid a
//! `core -> eth2util -> crypto -> core` crate dependency cycle.

use pluto_eth2api::spec::phase0;

use crate::types::{self, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

/// Converts a [`types::Signature`] into an eth2 phase0
/// [`phase0::BLSSignature`].
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
    let key: [u8; PRIVATE_KEY_LENGTH] = data.try_into().map_err(|_| ConvError::InvalidLength {
        expected: PRIVATE_KEY_LENGTH,
        got: data.len(),
    })?;
    Ok(key)
}

/// Returns a [`types::PublicKey`] from the given byte slice.
///
/// Returns an error if the data isn't exactly [`PUBLIC_KEY_LENGTH`] bytes.
pub fn pubkey_from_bytes(data: &[u8]) -> Result<types::PublicKey, ConvError> {
    let key: [u8; PUBLIC_KEY_LENGTH] = data.try_into().map_err(|_| ConvError::InvalidLength {
        expected: PUBLIC_KEY_LENGTH,
        got: data.len(),
    })?;
    Ok(key)
}

/// Returns a [`types::Signature`] from the given byte slice.
///
/// Returns an error if the data isn't exactly [`SIGNATURE_LENGTH`] bytes.
pub fn signature_from_bytes(data: &[u8]) -> Result<types::Signature, ConvError> {
    let sig: [u8; SIGNATURE_LENGTH] = data.try_into().map_err(|_| ConvError::InvalidLength {
        expected: SIGNATURE_LENGTH,
        got: data.len(),
    })?;
    Ok(sig)
}

/// Conversion error.
#[derive(Debug, thiserror::Error)]
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
    use test_case::test_case;

    use super::*;

    #[test_case(&[], PRIVATE_KEY_LENGTH, 0 ; "empty input")]
    #[test_case(&[42u8; PRIVATE_KEY_LENGTH + 1], PRIVATE_KEY_LENGTH, PRIVATE_KEY_LENGTH + 1 ; "more data than expected")]
    #[test_case(&[42u8; PRIVATE_KEY_LENGTH - 1], PRIVATE_KEY_LENGTH, PRIVATE_KEY_LENGTH - 1 ; "less data than expected")]
    fn privkey_from_bytes_invalid(data: &[u8], expected: usize, got: usize) {
        assert!(matches!(
            privkey_from_bytes(data),
            Err(ConvError::InvalidLength { expected: e, got: g }) if e == expected && g == got
        ));
    }

    #[test]
    fn privkey_from_bytes_valid() {
        let data = vec![42u8; PRIVATE_KEY_LENGTH];
        let key = privkey_from_bytes(&data).unwrap();
        assert_eq!(key, [42u8; PRIVATE_KEY_LENGTH]);
    }

    #[test_case(&[], PUBLIC_KEY_LENGTH, 0 ; "empty input")]
    #[test_case(&[42u8; PUBLIC_KEY_LENGTH + 1], PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH + 1 ; "more data than expected")]
    #[test_case(&[42u8; PUBLIC_KEY_LENGTH - 1], PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH - 1 ; "less data than expected")]
    fn pubkey_from_bytes_invalid(data: &[u8], expected: usize, got: usize) {
        assert!(matches!(
            pubkey_from_bytes(data),
            Err(ConvError::InvalidLength { expected: e, got: g }) if e == expected && g == got
        ));
    }

    #[test]
    fn pubkey_from_bytes_valid() {
        let data = vec![42u8; PUBLIC_KEY_LENGTH];
        let key = pubkey_from_bytes(&data).expect("should succeed");
        assert_eq!(key, [42u8; PUBLIC_KEY_LENGTH]);
    }

    #[test]
    fn pubkey_to_eth2_roundtrip() {
        let data = vec![42u8; PUBLIC_KEY_LENGTH];
        let pubkey = pubkey_from_bytes(&data).expect("should succeed");
        let res = pubkey_to_eth2(pubkey);
        assert_eq!(pubkey[..], res[..]);
    }

    #[test_case(&[], SIGNATURE_LENGTH, 0 ; "empty input")]
    #[test_case(&[42u8; SIGNATURE_LENGTH + 1], SIGNATURE_LENGTH, SIGNATURE_LENGTH + 1 ; "more data than expected")]
    #[test_case(&[42u8; SIGNATURE_LENGTH - 1], SIGNATURE_LENGTH, SIGNATURE_LENGTH - 1 ; "less data than expected")]
    fn signature_from_bytes_invalid(data: &[u8], expected: usize, got: usize) {
        assert!(matches!(
            signature_from_bytes(data),
            Err(ConvError::InvalidLength { expected: e, got: g }) if e == expected && g == got
        ));
    }

    #[test]
    fn signature_from_bytes_valid() {
        let data = vec![42u8; SIGNATURE_LENGTH];
        let sig = signature_from_bytes(&data).expect("should succeed");
        assert_eq!(sig, [42u8; SIGNATURE_LENGTH]);
    }

    #[test]
    fn sig_to_eth2_roundtrip() {
        let data = vec![42u8; SIGNATURE_LENGTH];
        let sig = signature_from_bytes(&data).expect("should succeed");
        let eth2_sig = sig_to_eth2(sig);
        assert_eq!(sig[..], eth2_sig[..]);
    }
}
