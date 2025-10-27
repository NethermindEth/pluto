// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business
// Source License 1.1

//! # Type Conversions for TBLS
//!
//! This module provides conversion utilities between different representations
//! of cryptographic types used in the Charon distributed validator.
//!
//! It handles conversions between:
//! - Raw byte slices and typed structures
//! - Different type representations across module boundaries
//! - Validation of byte lengths during conversions

use crate::types::{
    Error, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PrivateKey, PublicKey, SIGNATURE_LENGTH,
    Signature,
};

/// Converts a byte slice into a `PrivateKey`.
///
/// # Arguments
///
/// * `data` - Raw bytes representing a private key
///
/// # Returns
///
/// A 32-byte private key array
///
/// # Errors
///
/// Returns an error if the data length doesn't match the expected private key
/// length (32 bytes).
///
/// # Examples
///
/// ```
/// use charon_crypto::tblsconv::privkey_from_bytes;
///
/// let bytes = [1u8; 32];
/// let privkey = privkey_from_bytes(&bytes).unwrap();
/// ```
pub fn privkey_from_bytes(data: &[u8]) -> Result<PrivateKey, Error> {
    if data.len() != PRIVATE_KEY_LENGTH {
        return Err(Error::InvalidSecretKeyLength {
            expected: PRIVATE_KEY_LENGTH,
            got: data.len(),
        });
    }

    let mut key = [0u8; PRIVATE_KEY_LENGTH];
    key.copy_from_slice(data);
    Ok(key)
}

/// Converts a byte slice into a `PublicKey`.
///
/// # Arguments
///
/// * `data` - Raw bytes representing a public key
///
/// # Returns
///
/// A 48-byte public key array
///
/// # Errors
///
/// Returns an error if the data length doesn't match the expected public key
/// length (48 bytes).
///
/// # Examples
///
/// ```
/// use charon_crypto::tblsconv::pubkey_from_bytes;
///
/// let bytes = [1u8; 48];
/// let pubkey = pubkey_from_bytes(&bytes).unwrap();
/// ```
pub fn pubkey_from_bytes(data: &[u8]) -> Result<PublicKey, Error> {
    if data.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidPublicKeyLength {
            expected: PUBLIC_KEY_LENGTH,
            got: data.len(),
        });
    }

    let mut key = [0u8; PUBLIC_KEY_LENGTH];
    key.copy_from_slice(data);
    Ok(key)
}

/// Converts a byte slice into a `Signature`.
///
/// # Arguments
///
/// * `data` - Raw bytes representing a signature
///
/// # Returns
///
/// A 97-byte signature array
///
/// # Errors
///
/// Returns an error if the data length doesn't match the expected signature
/// length (97 bytes).
///
/// # Examples
///
/// ```
/// use charon_crypto::tblsconv::signature_from_bytes;
///
/// let bytes = [1u8; 97];
/// let signature = signature_from_bytes(&bytes).unwrap();
/// ```
pub fn signature_from_bytes(data: &[u8]) -> Result<Signature, Error> {
    if data.len() != SIGNATURE_LENGTH {
        return Err(Error::InvalidSignatureLength {
            expected: SIGNATURE_LENGTH,
            got: data.len(),
        });
    }

    let mut sig = [0u8; SIGNATURE_LENGTH];
    sig.copy_from_slice(data);
    Ok(sig)
}

/// Converts a `PrivateKey` into a byte slice.
///
/// # Arguments
///
/// * `key` - A private key
///
/// # Returns
///
/// A reference to the underlying 32-byte array
///
/// # Examples
///
/// ```
/// use charon_crypto::tblsconv::privkey_to_bytes;
///
/// let privkey = [1u8; 32];
/// let bytes = privkey_to_bytes(&privkey);
/// assert_eq!(bytes.len(), 32);
/// ```
#[inline]
pub fn privkey_to_bytes(key: &PrivateKey) -> &[u8] {
    key.as_slice()
}

/// Converts a `PublicKey` into a byte slice.
///
/// # Arguments
///
/// * `key` - A public key
///
/// # Returns
///
/// A reference to the underlying 48-byte array
///
/// # Examples
///
/// ```
/// use charon_crypto::tblsconv::pubkey_to_bytes;
///
/// let pubkey = [1u8; 48];
/// let bytes = pubkey_to_bytes(&pubkey);
/// assert_eq!(bytes.len(), 48);
/// ```
#[inline]
pub fn pubkey_to_bytes(key: &PublicKey) -> &[u8] {
    key.as_slice()
}

/// Converts a `Signature` into a byte slice.
///
/// # Arguments
///
/// * `sig` - A signature
///
/// # Returns
///
/// A reference to the underlying 97-byte array
///
/// # Examples
///
/// ```
/// use charon_crypto::tblsconv::signature_to_bytes;
///
/// let signature = [1u8; 97];
/// let bytes = signature_to_bytes(&signature);
/// assert_eq!(bytes.len(), 97);
/// ```
#[inline]
pub fn signature_to_bytes(sig: &Signature) -> &[u8] {
    sig.as_slice()
}

/// Converts a `PrivateKey` into a `Vec<u8>`.
///
/// # Arguments
///
/// * `key` - A private key
///
/// # Returns
///
/// A vector containing the 32-byte private key
///
/// # Examples
///
/// ```
/// use charon_crypto::tblsconv::privkey_to_vec;
///
/// let privkey = [1u8; 32];
/// let vec = privkey_to_vec(&privkey);
/// assert_eq!(vec.len(), 32);
/// ```
#[inline]
pub fn privkey_to_vec(key: &PrivateKey) -> Vec<u8> {
    key.to_vec()
}

/// Converts a `PublicKey` into a `Vec<u8>`.
///
/// # Arguments
///
/// * `key` - A public key
///
/// # Returns
///
/// A vector containing the 48-byte public key
///
/// # Examples
///
/// ```
/// use charon_crypto::tblsconv::pubkey_to_vec;
///
/// let pubkey = [1u8; 48];
/// let vec = pubkey_to_vec(&pubkey);
/// assert_eq!(vec.len(), 48);
/// ```
#[inline]
pub fn pubkey_to_vec(key: &PublicKey) -> Vec<u8> {
    key.to_vec()
}

/// Converts a `Signature` into a `Vec<u8>`.
///
/// # Arguments
///
/// * `sig` - A signature
///
/// # Returns
///
/// A vector containing the 97-byte signature
///
/// # Examples
///
/// ```
/// use charon_crypto::tblsconv::signature_to_vec;
///
/// let signature = [1u8; 97];
/// let vec = signature_to_vec(&signature);
/// assert_eq!(vec.len(), 97);
/// ```
#[inline]
pub fn signature_to_vec(sig: &Signature) -> Vec<u8> {
    sig.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privkey_from_bytes_valid() {
        let data = [42u8; PRIVATE_KEY_LENGTH];
        let result = privkey_from_bytes(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_privkey_from_bytes_invalid_length() {
        let data = [42u8; 16]; // Wrong length
        let result = privkey_from_bytes(&data);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidSecretKeyLength {
                expected: 32,
                got: 16
            }
        ));
    }

    #[test]
    fn test_pubkey_from_bytes_valid() {
        let data = [42u8; PUBLIC_KEY_LENGTH];
        let result = pubkey_from_bytes(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_pubkey_from_bytes_invalid_length() {
        let data = [42u8; 32]; // Wrong length
        let result = pubkey_from_bytes(&data);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPublicKeyLength {
                expected: 48,
                got: 32
            }
        ));
    }

    #[test]
    fn test_signature_from_bytes_valid() {
        let data = [42u8; SIGNATURE_LENGTH];
        let result = signature_from_bytes(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_signature_from_bytes_invalid_length() {
        let data = [42u8; 96]; // Wrong length
        let result = signature_from_bytes(&data);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidSignatureLength {
                expected: 97,
                got: 96
            }
        ));
    }

    #[test]
    fn test_privkey_roundtrip() {
        let original = [42u8; PRIVATE_KEY_LENGTH];
        let bytes = privkey_to_bytes(&original);
        let converted = privkey_from_bytes(bytes).unwrap();
        assert_eq!(original, converted);
    }

    #[test]
    fn test_pubkey_roundtrip() {
        let original = [42u8; PUBLIC_KEY_LENGTH];
        let bytes = pubkey_to_bytes(&original);
        let converted = pubkey_from_bytes(bytes).unwrap();
        assert_eq!(original, converted);
    }

    #[test]
    fn test_signature_roundtrip() {
        let original = [42u8; SIGNATURE_LENGTH];
        let bytes = signature_to_bytes(&original);
        let converted = signature_from_bytes(bytes).unwrap();
        assert_eq!(original, converted);
    }

    #[test]
    fn test_privkey_to_vec() {
        let key = [42u8; PRIVATE_KEY_LENGTH];
        let vec = privkey_to_vec(&key);
        assert_eq!(vec.len(), PRIVATE_KEY_LENGTH);
        assert_eq!(vec.as_slice(), &key);
    }

    #[test]
    fn test_pubkey_to_vec() {
        let key = [42u8; PUBLIC_KEY_LENGTH];
        let vec = pubkey_to_vec(&key);
        assert_eq!(vec.len(), PUBLIC_KEY_LENGTH);
        assert_eq!(vec.as_slice(), &key);
    }

    #[test]
    fn test_signature_to_vec() {
        let sig = [42u8; SIGNATURE_LENGTH];
        let vec = signature_to_vec(&sig);
        assert_eq!(vec.len(), SIGNATURE_LENGTH);
        assert_eq!(vec.as_slice(), &sig);
    }

    #[test]
    fn test_empty_slice_fails() {
        let empty: &[u8] = &[];

        assert!(privkey_from_bytes(empty).is_err());
        assert!(pubkey_from_bytes(empty).is_err());
        assert!(signature_from_bytes(empty).is_err());
    }

    #[test]
    fn test_oversized_slice_fails() {
        let data = vec![0u8; 1000];

        assert!(privkey_from_bytes(&data).is_err());
        assert!(pubkey_from_bytes(&data).is_err());
        assert!(signature_from_bytes(&data).is_err());
    }
}
