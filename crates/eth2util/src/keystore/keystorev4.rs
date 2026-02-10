//! Keystore v4 encryption and decryption (EIP-2335)
//!
//! This module implements EIP-2335 keystore version 4 encryption and decryption
//! using PBKDF2 and AES-128-CTR cipher.

use super::error::{KeystoreError, Result};

/// Default PBKDF2 cost (2^18).
const DEFAULT_COST: u32 = 262_144;

/// EIP-2335 keystore version.
pub(crate) const EIP2335_KEYSTORE_VERSION: u32 = 4;

/// The crypto section of an EIP-2335 keystore.
pub(crate) type CryptoSection = eth2_keystore::json_keystore::Crypto;

/// Encrypt a secret using PBKDF2-based EIP-2335 keystore encryption via
/// Lighthouse.
pub(crate) fn encrypt(
    secret: &[u8],
    password: &str,
    pbkdf2_c: Option<u32>,
) -> Result<CryptoSection> {
    if secret.len() != 32 {
        return Err(KeystoreError::Encrypt(format!(
            "invalid secret length: expected 32, got {}",
            secret.len()
        )));
    }

    let c = pbkdf2_c.unwrap_or(DEFAULT_COST);

    let mut rng = rand::thread_rng();
    let mut salt = vec![0u8; eth2_keystore::SALT_SIZE];
    rand::RngCore::fill_bytes(&mut rng, &mut salt);
    let mut iv_bytes = vec![0u8; eth2_keystore::IV_SIZE];
    rand::RngCore::fill_bytes(&mut rng, &mut iv_bytes);

    // Create KDF (PBKDF2)
    let kdf = eth2_keystore::json_keystore::Kdf::Pbkdf2(eth2_keystore::json_keystore::Pbkdf2 {
        c,
        dklen: eth2_keystore::DKLEN,
        prf: eth2_keystore::json_keystore::Prf::HmacSha256,
        salt: salt.into(),
    });

    // Create cipher (AES-128-CTR)
    let cipher =
        eth2_keystore::json_keystore::Cipher::Aes128Ctr(eth2_keystore::json_keystore::Aes128Ctr {
            iv: iv_bytes.into(),
        });

    let (ciphertext, checksum) = eth2_keystore::encrypt(secret, password.as_bytes(), &kdf, &cipher)
        .map_err(|e| KeystoreError::Encrypt(format!("{:?}", e)))?;

    Ok(eth2_keystore::json_keystore::Crypto {
        kdf: eth2_keystore::json_keystore::KdfModule {
            function: kdf.function(),
            params: kdf,
            message: eth2_keystore::json_keystore::EmptyString,
        },
        checksum: {
            // Note: The checksum function type is internal, so we have to deserialize from
            // JSON
            let checksum_json = serde_json::json!({
                "function": "sha256",
                "params": {},
                "message": hex::encode(checksum),
            });
            serde_json::from_value(checksum_json)
                .map_err(|e| KeystoreError::Encrypt(format!("checksum serialization: {}", e)))?
        },
        cipher: eth2_keystore::json_keystore::CipherModule {
            function: cipher.function(),
            params: cipher,
            message: ciphertext.into(),
        },
    })
}

/// Decrypt an EIP-2335 keystore crypto section using Lighthouse.
pub(crate) fn decrypt(crypto: &CryptoSection, password: &str) -> Result<Vec<u8>> {
    // Use eth2_keystore's decrypt function
    let plaintext = eth2_keystore::decrypt(password.as_bytes(), crypto).map_err(|e| match e {
        eth2_keystore::Error::InvalidPassword => {
            KeystoreError::Decrypt("invalid password or checksum failed".to_string())
        }
        eth2_keystore::Error::InvalidJson(msg) => {
            KeystoreError::Decrypt(format!("invalid JSON: {}", msg))
        }
        other => KeystoreError::Decrypt(format!("{:?}", other)),
    })?;

    Ok(plaintext.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(&[] => matches Err(_) ; "empty secret")]
    #[test_case(b"" => matches Err(_) ; "zero length secret")]
    #[test_case(b"short" => matches Err(_) ; "short secret")]
    fn encrypt_invalid_length(secret: &[u8]) -> Result<CryptoSection> {
        encrypt(secret, "test", Some(16))
    }

    #[test]
    fn encrypt_good() {
        let secret = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let password = "wallet passphrase";

        let crypto = encrypt(&secret, password, Some(1024)).unwrap();
        let decrypted = decrypt(&crypto, password).unwrap();

        assert_eq!(secret.as_slice(), decrypted.as_slice());
    }

    #[test_case([0u8; 32], "" ; "empty password")]
    #[test_case([0x42u8; 32], "test" ; "normal input")]
    fn encrypt_valid(secret: [u8; 32], password: &str) {
        let result = encrypt(&secret, password, Some(1024));
        assert!(result.is_ok());
    }

    #[test_case(
        r#"{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"#,
        "testpassword",
        vec![0x11, 0xdd, 0x0c, 0x87, 0xfe, 0xf7, 0x48, 0xdc, 0x07, 0xee, 0xb7, 0x0e, 0x0d, 0xe5, 0xdc, 0x94, 0x4c, 0xd4, 0xd5, 0xbe, 0x86, 0x4e, 0x0c, 0x40, 0x35, 0x26, 0xf2, 0xfd, 0x34, 0x61, 0xa8, 0x3e]
        ; "pbkdf2 with ascii password"
    )]
    #[test_case(
        r#"{"checksum":{"function":"sha256","message":"3e1d45e3e47bcb2406ab25b6119225c85e7b2276b0834c7203a125bd7b6ca34f","params":{}},"cipher":{"function":"aes-128-ctr","message":"0ed64a392274f7fcc76f8cf4d22f86057c42e6c6b726cc19dc64e80ebab5d1dd","params":{"iv":"ff6cc499ff4bbfca0125700b29cfa4dc"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"70f3ebd9776781f46c2ead400a3a9ed7ad2880871fe9422a734303d1492f2477"}}}"#,
        "testpasswordü",
        vec![0x3f, 0xa3, 0xc2, 0xa1, 0xc9, 0xf5, 0xe6, 0xb3, 0x5b, 0x22, 0x3b, 0x8e, 0x84, 0xcc, 0xb3, 0x94, 0x83, 0x77, 0x20, 0xa7, 0x12, 0xbb, 0xd1, 0xdc, 0xdd, 0xcf, 0xeb, 0x78, 0xa2, 0x98, 0xd0, 0x63]
        ; "pbkdf2 with unicode password"
    )]
    #[test_case(
        r#"{"checksum":{"function":"sha256","message":"a230c7d50dc1e141433559a12cedbe2db2014012b7d5bcda08f399d06ec9bd87","params":{}},"cipher":{"function":"aes-128-ctr","message":"5263382e2ae83dd06020baac533e0173f195be6726f362a683de885c0bdc8e0cec93a411ebc10dfccf8408e23a0072fadc581ab1fcd7a54faae8d2db0680fa76","params":{"iv":"c6437d26eb11abafd373bfb470fd0ad4"}},"kdf":{"function":"scrypt","message":"","params":{"dklen":32,"n":16,"p":8,"r":1,"salt":"20c085c4048f5592cc36bb2a6aa16f0d887f4eb4110849830ceb1eb2dfc0d1be"}}}"#,
        "wallet passphrase",
        vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]
        ; "scrypt kdf"
    )]
    fn decrypt_valid(input: &str, passphrase: &str, expected: Vec<u8>) {
        let crypto: CryptoSection = serde_json::from_str(input).unwrap();
        let output = decrypt(&crypto, passphrase).unwrap();
        assert_eq!(expected, output);
    }

    #[test_case(
        r#"{"checksum":{"function":"sha256","message":"0ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"#,
        "testpassword"
        ; "invalid checksum"
    )]
    fn decrypt_should_fail(input: &str, passphrase: &str) {
        let crypto: CryptoSection = serde_json::from_str(input).unwrap();
        let result = decrypt(&crypto, passphrase);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid password or checksum")
        );
    }

    #[test_case(r#"{"checksum":{"function":"sha256","message":"hb9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"# ; "bad checksum message")]
    #[test_case(r#"{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"h12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"# ; "bad cipher message")]
    #[test_case(r#"{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"h29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"# ; "bad iv")]
    #[test_case(r#"{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"hbd90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"# ; "bad salt")]
    fn decrypt_invalid_json(input: &str) {
        let result = serde_json::from_str::<CryptoSection>(input);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let secret = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let password = "testpassword";

        // Use low cost for fast testing
        let crypto = encrypt(secret, password, Some(16)).unwrap();
        let decrypted = decrypt(&crypto, password).unwrap();

        assert_eq!(secret.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn decrypt_wrong_password() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let password = "correctpassword";

        let crypto = encrypt(secret, password, Some(16)).unwrap();
        let result = decrypt(&crypto, "wrongpassword");

        assert!(result.is_err());
    }
}
