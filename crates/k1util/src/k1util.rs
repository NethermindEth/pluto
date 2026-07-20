//! # k1util
//!
//! Helper functions for working with secp256k1 keys.

use std::path::Path;

use k256::{
    AffinePoint, FieldBytes, PublicKey, SecretKey,
    ecdsa::{self, RecoveryId, Signature, SigningKey, hazmat::VerifyPrimitive},
};
use libp2p::identity::PublicKey as Libp2pPublicKey;

/// `SCALAR_LEN` is the length of secp256k1 scalar.
pub const SCALAR_LEN: usize = 32;

/// `K1_HASH_LEN`` is the length of secp256k1 signature hash/digest.
pub const K1_HASH_LEN: usize = 32;

/// `SIGNATURE_LEN` is the length of secp256k1 signature.
pub const SIGNATURE_LEN: usize = 65;

/// `SIGNATURE_LEN_WITHOUT_V` is the length of secp256k1 signature without the
/// recovery id.
pub const SIGNATURE_LEN_WITHOUT_V: usize = SIGNATURE_LEN - 1;

/// `K1_REC_IDX` is the Ethereum format secp256k1 signature recovery id index.
pub const K1_REC_IDX: usize = 64;

/// An error that can occur when verifying a secp256k1 signature.
#[derive(Debug, thiserror::Error)]
pub enum K1UtilError {
    /// The signature length is invalid.
    #[error("The signature length is invalid: expected {expected}, actual {actual}")]
    InvalidSignatureLength {
        /// The expected signature length.
        expected: usize,
        /// The actual signature length.
        actual: usize,
    },

    /// Failed to parse the signature.
    #[error("Failed to parse the signature: {0}")]
    InvalidSignature(ecdsa::Error),

    /// The hash length is invalid.
    #[error("The hash length is invalid: expected {K1_HASH_LEN}, actual {actual}")]
    InvalidHashLength {
        /// The actual hash length.
        actual: usize,
    },

    /// The signature recovery id is invalid.
    #[error("The signature recovery id byte {invalid_recovery_byte} is invalid")]
    InvalidSignatureRecoveryId {
        /// Invalid recovery id.
        invalid_recovery_byte: u8,
    },

    /// Failed to read the file.
    #[error("Failed to read the file: {0}")]
    FailedToReadFile(std::io::Error),

    /// Failed to write the file.
    #[error("Failed to write the file: {0}")]
    FailedToWriteFile(std::io::Error),

    /// Failed to decode the hex string.
    #[error("Failed to decode the hex string: {0}")]
    FailedToDecodeHex(#[from] hex::FromHexError),

    /// Failed to parse the secret key.
    #[error("Failed to parse the secret key: {0}")]
    FailedToParseSecretKey(k256::elliptic_curve::Error),

    /// Failed to parse the secp256k1 public key.
    #[error("Failed to parse the secp256k1 public key: {0}")]
    FailedToParseSecp256k1PublicKey(k256::elliptic_curve::Error),

    /// Failed to parse the libp2p public key.
    #[error("Failed to parse the libp2p public key: {0}")]
    FailedToParseLibp2pPublicKey(#[from] libp2p::identity::OtherVariantError),
}

type Result<T> = std::result::Result<T, K1UtilError>;

/// Converts a libp2p PublicKey to a secp256k1 PublicKey.
pub fn public_key_from_libp2p(pk: &Libp2pPublicKey) -> Result<PublicKey> {
    let secp_key = pk.clone().try_into_secp256k1()?;
    PublicKey::from_sec1_bytes(&secp_key.to_bytes())
        .map_err(K1UtilError::FailedToParseSecp256k1PublicKey)
}

/// Sign returns a signature from input data.
/// The produced signature is 65 bytes in the [R || S || V] format where V is 0
/// or 1.
pub fn sign(key: &SecretKey, hash: &[u8]) -> Result<[u8; SIGNATURE_LEN]> {
    if hash.len() != K1_HASH_LEN {
        return Err(K1UtilError::InvalidHashLength { actual: hash.len() });
    }

    let mut hash_bytes = [0u8; K1_HASH_LEN];
    hash_bytes.copy_from_slice(hash);

    let secp = SigningKey::from(key);

    let (signature, recovery_id) = secp
        .sign_prehash_recoverable(&hash_bytes)
        .map_err(K1UtilError::InvalidSignature)?;

    let mut result = [0u8; SIGNATURE_LEN];

    // Copy R || S (64 bytes)
    result[..64].copy_from_slice(&signature.to_bytes());

    // Append V (recovery byte, already 0 or 1)
    result[64] = recovery_id.to_byte();

    Ok(result)
}

/// Verify65 verifies a 65 byte signature.
pub fn verify_65(pubkey: &PublicKey, hash: &[u8], sig: &[u8]) -> Result<bool> {
    let recovered = recover(hash, sig)?;

    Ok(recovered == *pubkey)
}

/// verify_64 returns whether the 64 byte signature is valid for the provided
/// hash and secp256k1 public key.
///
/// Note the signature MUST be 64 bytes in the [R || S] format without recovery
/// ID.
pub fn verify_64(pubkey: &PublicKey, hash: &[u8], sig: &[u8]) -> Result<bool> {
    if sig.len() != 2 * SCALAR_LEN {
        return Err(K1UtilError::InvalidSignatureLength {
            expected: 2 * SCALAR_LEN,
            actual: sig.len(),
        });
    }

    if hash.len() != K1_HASH_LEN {
        return Err(K1UtilError::InvalidHashLength { actual: hash.len() });
    }

    let signature = Signature::from_slice(sig).map_err(K1UtilError::InvalidSignature)?;

    let verifying_key: AffinePoint = pubkey.into();

    #[allow(deprecated)] // todo(varex83): remove this when new k256 version is released
    let field_bytes = FieldBytes::from_slice(hash);

    Ok(verifying_key
        .verify_prehashed(field_bytes, &signature)
        .is_ok())
}

/// Recover recovers the public key from a signature.
pub fn recover(hash: &[u8], sig: &[u8]) -> Result<PublicKey> {
    if hash.len() != K1_HASH_LEN {
        return Err(K1UtilError::InvalidHashLength { actual: hash.len() });
    }

    if sig.len() != SIGNATURE_LEN {
        return Err(K1UtilError::InvalidSignatureLength {
            expected: SIGNATURE_LEN,
            actual: sig.len(),
        });
    }

    let original_recovery_byte = sig[K1_REC_IDX];

    // Charon accepts only the Ethereum-format recovery ids {0, 1} and their
    // Bitcoin-compact-format equivalents {27, 28}. Reject everything else
    // (notably the x-reduced ids 2 and 3 that `RecoveryId::from_byte` would
    // otherwise accept). See charon app/k1util/k1util.go Recover @ v1.7.1.
    let recovery_byte = match original_recovery_byte {
        0 | 1 => original_recovery_byte,
        // 27/28 are the Bitcoin-compact-format equivalents of 0/1.
        27 => 0,
        28 => 1,
        _ => {
            return Err(K1UtilError::InvalidSignatureRecoveryId {
                invalid_recovery_byte: original_recovery_byte,
            });
        }
    };

    let mut signature =
        Signature::from_slice(&sig[..SIGNATURE_LEN - 1]).map_err(K1UtilError::InvalidSignature)?;

    // `recovery_byte` is guaranteed to be 0 or 1 here, so `from_byte` is
    // infallible.
    let mut recovery_id = RecoveryId::from_byte(recovery_byte)
        .expect("recovery byte is 0 or 1, which is always a valid recovery id");

    // Charon's decred-backed `Recover` accepts high-S signatures — it only
    // rejects `S == 0` and `S >= group order` (no low-S rule). k256's
    // `recover_from_prehash` self-verifies and rejects high-S outright. Since
    // negating S (mod n) and flipping the recovery-id parity recovers the
    // *same* public key, canonicalizing to low-S here preserves Charon's
    // acceptance domain without changing the recovered key.
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
        recovery_id = RecoveryId::from_byte(recovery_id.to_byte() ^ 1)
            .expect("flipping the parity of a 0/1 recovery id stays in {0, 1}");
    }

    let pubkey = ecdsa::VerifyingKey::recover_from_prehash(hash, &signature, recovery_id)
        .map_err(K1UtilError::InvalidSignature)?;

    Ok(pubkey.into())
}

/// Load loads a secret key from a file.
pub fn load(file: &Path) -> Result<SecretKey> {
    let contents = std::fs::read_to_string(file).map_err(K1UtilError::FailedToReadFile)?;

    let decoded = hex::decode(contents.trim())?;

    let key = SecretKey::from_slice(&decoded).map_err(K1UtilError::FailedToParseSecretKey)?;

    Ok(key)
}

/// Save saves a secret key to a file.
///
/// On unix the file is created with mode `0o600` (owner read/write only),
/// matching Charon's `app/k1util/k1util.go` `Save` which writes via
/// `os.WriteFile(file, ..., 0o600)`. This prevents the private key from being
/// world-readable.
pub fn save(key: &SecretKey, file: &Path) -> Result<()> {
    let encoded = hex::encode(key.to_bytes());

    #[cfg(unix)]
    {
        use std::{
            io::Write as _,
            os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
        };

        // Create with `0o600` so the key is never momentarily world-readable.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(file)
            .map_err(K1UtilError::FailedToWriteFile)?;

        // `mode(0o600)` only applies on creation; force it for an existing file
        // too so an overwrite can never leave looser permissions in place.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(K1UtilError::FailedToWriteFile)?;

        f.write_all(encoded.as_bytes())
            .map_err(K1UtilError::FailedToWriteFile)?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(file, encoded).map_err(K1UtilError::FailedToWriteFile)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::rand_core::OsRng;
    use std::io::Write;
    use test_case::test_case;

    use super::*;

    const PRIV_KEY_1: &str = "41d3ff12045b73c870529fe44f70dca2745bafbe1698ffc3c8759eef3cfbaee1";
    const PUB_KEY_1: &str = "02bc8e7cdb50e0ffd52a54faf984d6ac8fe5ee6856d38a5f8acd9bd33fc9c7d50d";
    const DIGEST_1: &str = "52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649";
    const SIG_1: &str = "e08097bed6dc40d70aa0076f9d8250057566cdf40c652b3785ad9c06b1e38d584f8f331bf46f68e3737823a3bda905e90ca96735d510a6934b215753c09acec201";

    #[test]
    fn k1_util() {
        let key_bytes = hex::decode(PRIV_KEY_1).unwrap();
        let key = SecretKey::from_slice(&key_bytes).unwrap();

        assert_eq!(key.to_bytes().to_vec(), key_bytes, "Key bytes should match");

        let digest = hex::decode(DIGEST_1).unwrap();

        let sig = sign(&key, &digest).unwrap();

        let sig_expected = hex::decode(SIG_1).unwrap();

        assert_eq!(sig.to_vec(), sig_expected, "Signature should match");

        let verified = verify_65(&key.public_key(), &digest, &sig).unwrap();
        assert!(
            verified,
            "Signature should be verified by 65 byte signature"
        );

        let verified = verify_64(&key.public_key(), &digest, &sig[..SIGNATURE_LEN - 1]).unwrap();
        assert!(
            verified,
            "Signature should be verified by 64 byte signature"
        );

        let recovered = recover(&digest, &sig).unwrap();
        assert_eq!(
            recovered.to_sec1_bytes().to_vec(),
            hex::decode(PUB_KEY_1).unwrap(),
            "Recovered public key should match"
        );
    }

    #[test]
    fn random_works() {
        let key = SecretKey::random(&mut OsRng);

        let digest = vec![0u8; K1_HASH_LEN];

        let sig = sign(&key, &digest).unwrap();

        let verified = verify_65(&key.public_key(), &digest, &sig).unwrap();
        assert!(
            verified,
            "Signature should be verified by 65 byte signature"
        );

        let verified = verify_64(&key.public_key(), &digest, &sig[..SIGNATURE_LEN - 1]).unwrap();
        assert!(
            verified,
            "Signature should be verified by 64 byte signature"
        );

        let recovered = recover(&digest, &sig).unwrap();
        assert_eq!(
            recovered,
            key.public_key(),
            "Recovered public key should match"
        );
    }

    // Charon accepts only the Ethereum-format recovery ids {0, 1} and their
    // Bitcoin-compact equivalents {27, 28}. Everything else — including the
    // x-reduced ids 2/3 that k256's `RecoveryId::from_byte` would accept — must
    // be rejected with the original byte preserved in the error.
    #[test_case(0, true ; "eth id 0 accepted")]
    #[test_case(1, true ; "eth id 1 accepted")]
    #[test_case(27, true ; "bitcoin-compact 27 accepted")]
    #[test_case(28, true ; "bitcoin-compact 28 accepted")]
    #[test_case(2, false ; "x-reduced id 2 rejected")]
    #[test_case(3, false ; "x-reduced id 3 rejected")]
    #[test_case(4, false ; "out-of-domain 4 rejected")]
    #[test_case(26, false ; "out-of-domain 26 rejected")]
    #[test_case(29, false ; "out-of-domain 29 rejected")]
    #[test_case(255, false ; "out-of-domain 255 rejected")]
    fn recover_recovery_id_domain(recovery_byte: u8, accepted: bool) {
        // Produce a known-valid 65-byte signature (natural recovery byte 0 or
        // 1), then override the recovery byte to exercise the domain.
        let key = SecretKey::from_slice(&hex::decode(PRIV_KEY_1).unwrap()).unwrap();
        let digest = hex::decode(DIGEST_1).unwrap();
        let mut sig = sign(&key, &digest).unwrap();
        sig[K1_REC_IDX] = recovery_byte;

        let result = recover(&digest, &sig);
        if accepted {
            assert!(
                result.is_ok(),
                "recovery byte {recovery_byte} should be accepted"
            );
        } else {
            assert!(
                matches!(
                    result,
                    Err(K1UtilError::InvalidSignatureRecoveryId { invalid_recovery_byte })
                        if invalid_recovery_byte == recovery_byte
                ),
                "recovery byte {recovery_byte} should be rejected with InvalidSignatureRecoveryId carrying the original byte, got {:?}",
                result.map(|_| "Ok"),
            );
        }
    }

    #[test]
    fn recover_accepts_high_s() {
        // Charon's decred-backed `Recover` accepts high-S signatures; k256's
        // recovery self-verification rejects them. Build the high-S
        // malleability twin of a valid signature (s' = n - s, recovery-id
        // parity flipped) and confirm it recovers the same public key.
        let key = SecretKey::from_slice(&hex::decode(PRIV_KEY_1).unwrap()).unwrap();
        let digest = hex::decode(DIGEST_1).unwrap();
        let base_sig = sign(&key, &digest).unwrap();

        let low_s = Signature::from_slice(&base_sig[..SIGNATURE_LEN_WITHOUT_V]).unwrap();
        let (r, s) = low_s.split_scalars();
        let high_s = Signature::from_scalars(r, -s).unwrap();

        let mut sig = [0u8; SIGNATURE_LEN];
        sig[..SIGNATURE_LEN_WITHOUT_V].copy_from_slice(&high_s.to_bytes());
        sig[K1_REC_IDX] = base_sig[K1_REC_IDX] ^ 1;

        let recovered = recover(&digest, &sig).unwrap();
        assert_eq!(
            recovered,
            key.public_key(),
            "high-S signature must recover the same key as its low-S twin"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_private_key_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let key = SecretKey::random(&mut OsRng);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("charon-enr-private-key");

        save(&key, &path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "private key file must be mode 0o600");

        // The saved key must still round-trip through `load`.
        assert_eq!(load(&path).unwrap(), key, "saved key should round-trip");
    }

    #[cfg(unix)]
    #[test]
    fn save_tightens_permissions_when_overwriting_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("charon-enr-private-key");

        // Pre-create a world-readable file at the target path.
        std::fs::write(&path, "stale").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let key = SecretKey::random(&mut OsRng);
        save(&key, &path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "overwrite must tighten to mode 0o600");
        assert_eq!(load(&path).unwrap(), key);
    }

    #[test]
    fn load_nonexistent_file() {
        let file = Path::new("nonexistent-file");
        let result = load(file);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_hex_encoded_file() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        write!(temp_file, "abcXYZ123").unwrap(); // invalid hex encoded file

        let result = load(temp_file.path());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            K1UtilError::FailedToDecodeHex(_)
        ));
    }

    #[test]
    fn valid_hex_strings() {
        let key = SecretKey::random(&mut OsRng);
        let key_str = hex::encode(key.to_bytes()).to_string();

        let hex_strs = vec![
            format!("{}\n", key_str.clone()),
            format!("{}\r\n", key_str.clone()),
            format!("{} ", key_str.clone()),
            key_str.clone(),
        ];

        for hex_str in hex_strs {
            let mut temp_file = tempfile::NamedTempFile::new().unwrap();
            write!(temp_file, "{}", hex_str).unwrap();

            let result = load(Path::new(&temp_file.path()));
            assert!(
                result.is_ok(),
                "Failed to load key from file: {:?}",
                &hex_str[hex_str.len().saturating_sub(2)..].to_string()
            );
            assert_eq!(result.unwrap(), key, "Key should match");
        }
    }
}
