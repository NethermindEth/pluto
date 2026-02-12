//! Keystore v4 encryption and decryption (EIP-2335).

use aes::Aes128;
use cipher::{KeyIvInit, StreamCipher};
use pluto_crypto::types::PrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::error::{KeystoreError, Result};

/// The default iteraction count, `c`, for PBKDF2.
const DEFAULT_PBKDF2_C: u32 = 262_144;

/// The recommended scrypt parameter `n` (cost).
const DEFAULT_SCRYPT_N: u32 = 262_144;
/// The recommended scrypt parameter `p` (parallelization).
const DEFAULT_SCRYPT_P: u32 = 1;
/// The recommended scrypt parameter `r` (block size).
const DEFAULT_SCRYPT_R: u32 = 8;
/// The recommended scrypt memory requirement \(128*n*p*r\).
const DEFAULT_SCRYPT_NPR: u32 = 128 * DEFAULT_SCRYPT_N * DEFAULT_SCRYPT_P * DEFAULT_SCRYPT_R;

/// EIP-2335 keystore version.
pub(crate) const EIP2335_KEYSTORE_VERSION: u32 = 4;

/// The default byte length of the salt used to seed the KDF.
///
/// NOTE: there is no clear guidance in EIP-2335 regarding the size of this
/// salt. Neither [pbkdf2](https://www.ietf.org/rfc/rfc2898.txt) or [scrypt](https://tools.ietf.org/html/rfc7914)
/// make a clear statement about what size it should be, however 32-bytes
/// certainly seems reasonable and larger than the EITF examples.
const SALT_SIZE: usize = 32;

/// Size of the IV (initialization vector) used for aes-128-ctr encryption of
/// private key material.
///
/// NOTE: the EIP-2335 test vectors use a 16-byte IV whilst RFC3868 uses an
/// 8-byte IV. Reference:
///
/// - https://tools.ietf.org/html/rfc3686
/// - https://github.com/ethereum/EIPs/issues/2339#issuecomment-623865023
///
/// Comment from Carl B, author of EIP-2335:
///
/// AES CTR IV's should be the same length as the internal blocks in my
/// understanding. (The IV is the first block input.)
///
/// As far as I know, AES-128-CTR is not defined by the IETF, but by NIST in
/// SP800-38A. (https://csrc.nist.gov/publications/detail/sp/800-38a/final) The test vectors in this standard
/// are 16 bytes.
const IV_SIZE: usize = 16;

/// The length of the derived key.
const DKLEN: usize = 32;
const DKLEN_U32: u32 = 32;

/// The maximum PBKDF2 iteration count.
///
/// NIST Recommends suggests potential use cases where `c` of 10,000,000 is
/// desireable. As it is 10 years old this has been increased to 80,000,000.
/// Larger values will take over 1 minute to execute on an average machine.
///
/// Reference:
///
/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
const MAX_PBKDF2_C: u32 = 80_000_000;

/// AES-128-CTR stream cipher type.
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// The EIP-2335 keystore crypto module.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Crypto {
    pub kdf: KdfModule,
    pub checksum: ChecksumModule,
    pub cipher: CipherModule,
}

/// Used for ensuring serde only decodes an empty string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EmptyString;

impl From<EmptyString> for String {
    fn from(_from: EmptyString) -> String {
        "".into()
    }
}

impl TryFrom<String> for EmptyString {
    type Error = &'static str;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        if s.is_empty() {
            Ok(Self)
        } else {
            Err("must be empty string")
        }
    }
}

/// Used for ensuring serde only decodes an empty object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "serde_json::Value", into = "serde_json::Value")]
pub struct EmptyMap;

impl From<EmptyMap> for serde_json::Value {
    fn from(_from: EmptyMap) -> serde_json::Value {
        serde_json::json!({})
    }
}

impl TryFrom<serde_json::Value> for EmptyMap {
    type Error = &'static str;

    fn try_from(v: serde_json::Value) -> std::result::Result<Self, Self::Error> {
        match v {
            serde_json::Value::Object(map) if map.is_empty() => Ok(Self),
            _ => Err("must be empty map"),
        }
    }
}

/// To allow serde to encode/decode byte arrays from HEX ASCII strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl From<HexBytes> for String {
    fn from(from: HexBytes) -> String {
        hex::encode(from.0)
    }
}

impl TryFrom<String> for HexBytes {
    type Error = String;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        // Left-pad with a zero if there is not an even number of hex digits to ensure
        // `hex::decode` doesn't return an error.
        let s = if s.len().is_multiple_of(2) {
            s
        } else {
            format!("0{}", s)
        };

        hex::decode(s)
            .map(Self)
            .map_err(|e| format!("invalid hex: {e}"))
    }
}

/// Used for ensuring that serde only decodes a SHA-256 checksum function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumFunction {
    #[serde(rename = "sha256")]
    Sha256,
}

/// Checksum module representation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChecksumModule {
    pub function: ChecksumFunction,
    pub params: EmptyMap,
    pub message: HexBytes,
}

/// Used for ensuring that serde only decodes an AES-128-CTR cipher function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherFunction {
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr,
}

/// Cipher module representation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherModule {
    pub function: CipherFunction,
    pub params: Aes128CtrParams,
    pub message: HexBytes,
}

/// Parameters for AES-128-CTR.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aes128CtrParams {
    pub iv: HexBytes,
}

/// Used for ensuring that serde only decodes valid KDF functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum KdfFunction {
    Pbkdf2,
    Scrypt,
}

impl From<KdfFunction> for String {
    fn from(from: KdfFunction) -> String {
        match from {
            KdfFunction::Pbkdf2 => "pbkdf2".into(),
            KdfFunction::Scrypt => "scrypt".into(),
        }
    }
}

impl TryFrom<String> for KdfFunction {
    type Error = String;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        match s.as_str() {
            "pbkdf2" => Ok(Self::Pbkdf2),
            "scrypt" => Ok(Self::Scrypt),
            other => Err(format!("unsupported kdf function: {other}")),
        }
    }
}

/// PRF for use in PBKDF2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Prf {
    #[serde(rename = "hmac-sha256")]
    #[default]
    HmacSha256,
}

/// PBKDF2 parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pbkdf2Params {
    pub c: u32,
    pub dklen: u32,
    pub prf: Prf,
    pub salt: HexBytes,
}

/// Scrypt parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScryptParams {
    pub dklen: u32,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    pub salt: HexBytes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Kdf {
    Pbkdf2(Pbkdf2Params),
    Scrypt(ScryptParams),
}

/// KDF module representation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfModule {
    pub function: KdfFunction,
    pub params: Kdf,
    pub message: EmptyString,
}

// We only check the size of the `iv` is non-zero as there is no guidance about
// this on EIP-2335.
//
// Reference:
//
// - https://github.com/ethereum/EIPs/issues/2339#issuecomment-623865023
fn validate_aes_iv(iv: &[u8]) -> Result<()> {
    if iv.is_empty() {
        return Err(KeystoreError::Decrypt(format!(
            "invalid IV length: expected {IV_SIZE}, got {}",
            iv.len()
        )));
    } else if iv.len() != IV_SIZE {
        eprintln!(
            "WARN: AES IV length incorrect is {}, should be {}",
            iv.len(),
            IV_SIZE
        );
    }
    Ok(())
}

// Validates the kdf parameters to ensure they are sufficiently secure, in
// addition to preventing DoS attacks from excessively large parameters.
fn validate_parameters(kdf: &Kdf) -> Result<()> {
    match kdf {
        Kdf::Pbkdf2(params) => {
            // We always compute a derived key of 32 bytes so reject anything that says
            // otherwise.
            if params.dklen as usize != DKLEN {
                return Err(KeystoreError::InvalidPbkdf2Param);
            }

            // NIST Recommends suggests potential use cases where `c` of 10,000,000 is
            // desireable. As it is 10 years old this has been increased to
            // 80,000,000. Larger values will take over 1 minute to execute on
            // an average machine.
            //
            // Reference:
            //
            // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
            if params.c > MAX_PBKDF2_C {
                return Err(KeystoreError::InvalidPbkdf2Param);
            }

            // RFC2898 declares that `c` must be a "positive integer".
            //
            // Reference:
            //
            // https://www.ietf.org/rfc/rfc2898.txt
            if params.c < DEFAULT_PBKDF2_C {
                if params.c == 0 {
                    return Err(KeystoreError::InvalidPbkdf2Param);
                }
                eprintln!(
                    "WARN: PBKDF2 parameters are too weak, 'c' is {}, we recommend using {}",
                    params.c, DEFAULT_PBKDF2_C
                );
            }

            // Validate `salt` length.
            validate_salt(params.salt.as_bytes())?;
        }
        Kdf::Scrypt(params) => {
            // RFC7914 declares that all these parameters must be greater than 1:
            //
            // - `N`: costParameter.
            // - `r`: blockSize.
            // - `p`: parallelizationParameter
            //
            // Reference:
            //
            // https://tools.ietf.org/html/rfc7914
            if params.n <= 1 || params.r == 0 || params.p == 0 {
                return Err(KeystoreError::InvalidScryptParam);
            }

            // We always compute a derived key of 32 bytes so reject anything that says
            // otherwise.
            if params.dklen as usize != DKLEN {
                return Err(KeystoreError::InvalidScryptParam);
            }

            // Ensure that `n` is power of 2.
            let n = 1u32
                .checked_shl(log2_int(params.n))
                .ok_or(KeystoreError::InvalidScryptParam)?;
            if params.n != n {
                return Err(KeystoreError::InvalidScryptParam);
            }

            // Maximum Parameters
            //
            // Uses a u32 to store value thus maximum memory usage is 4GB.
            //
            // Note: Memory requirements = 128*n*p*r
            let npr = params
                .n
                .checked_mul(params.p)
                .and_then(|v| v.checked_mul(params.r))
                .and_then(|v| v.checked_mul(128))
                .ok_or(KeystoreError::InvalidScryptParam)?;

            // Minimum Parameters
            if npr < DEFAULT_SCRYPT_NPR {
                eprintln!(
                    "WARN: Scrypt parameters are too weak (n: {}, p: {}, r: {}), we recommend (n: {}, p: {}, r: {})",
                    params.n,
                    params.p,
                    params.r,
                    DEFAULT_SCRYPT_N,
                    DEFAULT_SCRYPT_P,
                    DEFAULT_SCRYPT_R
                );
            }

            // Validate `salt` length.
            validate_salt(params.salt.as_bytes())?;
        }
    }

    Ok(())
}

// Compute floor of log2 of a u32.
fn log2_int(x: u32) -> u32 {
    x.checked_ilog2().unwrap_or(0)
}

// Validates that the salt is non-zero in length.
// Emits a warning if the salt is outside reasonable bounds.
fn validate_salt(salt: &[u8]) -> Result<()> {
    if salt.is_empty() {
        return Err(KeystoreError::InvalidSaltLength);
    } else if salt.len() < SALT_SIZE / 2 {
        eprintln!(
            "WARN: Salt is too short {}, we recommend {}",
            salt.len(),
            SALT_SIZE
        );
    } else if salt.len() > SALT_SIZE * 2 {
        eprintln!(
            "WARN: Salt is too long {}, we recommend {}",
            salt.len(),
            SALT_SIZE
        );
    }
    Ok(())
}

/// Normalize a password per EIP-2335: NFKD normalize then strip control codes,
/// then UTF-8 encode.
///
/// Returns a [`Zeroizing`] wrapper so the normalized bytes are wiped on drop.
fn normalize_password(password: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        password
            .nfkd()
            .filter(|c| !c.is_control())
            .collect::<String>()
            .into_bytes(),
    )
}

fn derive_key(kdf: &Kdf, password: &[u8]) -> Result<Zeroizing<[u8; DKLEN]>> {
    let mut dk = Zeroizing::new([0u8; DKLEN]);

    match kdf {
        Kdf::Pbkdf2(params) => {
            pbkdf2::pbkdf2_hmac::<Sha256>(password, params.salt.as_bytes(), params.c, dk.as_mut());
        }
        Kdf::Scrypt(params) => {
            let log_n =
                u8::try_from(log2_int(params.n)).map_err(|_| KeystoreError::InvalidScryptParam)?;
            let scrypt_params = scrypt::Params::new(log_n, params.r, params.p, DKLEN)
                .map_err(|e| KeystoreError::ScryptParams(format!("{e}")))?;
            scrypt::scrypt(
                password,
                params.salt.as_bytes(),
                &scrypt_params,
                dk.as_mut(),
            )
            .map_err(|e| KeystoreError::Decrypt(format!("scrypt: {e}")))?;
        }
    }

    Ok(dk)
}

fn generate_checksum(dk: &[u8; DKLEN], cipher_message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&dk[16..32]);
    hasher.update(cipher_message);

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

/// Encrypt a secret using PBKDF2-based EIP-2335 keystore encryption.
///
/// Note: this implementation intentionally only *creates* PBKDF2 keystores.
/// Decryption supports both PBKDF2 and scrypt.
///
/// ## Errors
///
/// - If the PBKDF2 iteration count is zero.
pub(crate) fn encrypt(
    secret: &PrivateKey,
    password: &str,
    pbkdf2_c: Option<u32>,
    rng: &mut impl rand::RngCore,
) -> Result<Crypto> {
    let c = pbkdf2_c.unwrap_or(DEFAULT_PBKDF2_C);
    if c == 0 {
        return Err(KeystoreError::InvalidPbkdf2Param);
    }

    let mut salt = vec![0u8; SALT_SIZE];
    rng.fill_bytes(&mut salt);
    let mut iv = vec![0u8; IV_SIZE];
    rng.fill_bytes(&mut iv);

    let kdf = Kdf::Pbkdf2(Pbkdf2Params {
        c,
        dklen: DKLEN_U32,
        prf: Prf::HmacSha256,
        salt: salt.into(),
    });

    // Derive key and encrypt.
    let normalized = normalize_password(password);
    let dk = derive_key(&kdf, &normalized)?;

    let mut ciphertext = secret.to_vec();
    let mut aes_cipher = Aes128Ctr::new(
        cipher::generic_array::GenericArray::from_slice(&dk[..16]),
        cipher::generic_array::GenericArray::from_slice(&iv),
    );
    aes_cipher.apply_keystream(&mut ciphertext);

    let checksum = generate_checksum(&dk, &ciphertext);

    Ok(Crypto {
        kdf: KdfModule {
            function: KdfFunction::Pbkdf2,
            params: kdf,
            message: EmptyString,
        },
        checksum: ChecksumModule {
            function: ChecksumFunction::Sha256,
            params: EmptyMap,
            message: checksum.to_vec().into(),
        },
        cipher: CipherModule {
            function: CipherFunction::Aes128Ctr,
            params: Aes128CtrParams { iv: iv.into() },
            message: ciphertext.into(),
        },
    })
}

/// Decrypt an EIP-2335 keystore crypto section.
pub(crate) fn decrypt(crypto: &Crypto, password: &str) -> Result<Vec<u8>> {
    validate_parameters(&crypto.kdf.params)?;
    validate_aes_iv(crypto.cipher.params.iv.as_bytes())?;

    let normalized = normalize_password(password);
    let dk = derive_key(&crypto.kdf.params, &normalized)?;

    if &generate_checksum(&dk, crypto.cipher.message.as_bytes())[..]
        != crypto.checksum.message.as_bytes()
    {
        return Err(KeystoreError::InvalidChecksum);
    }

    let mut plaintext = crypto.cipher.message.as_bytes().to_vec();
    let mut aes_cipher = Aes128Ctr::new(
        cipher::generic_array::GenericArray::from_slice(&dk[..16]),
        cipher::generic_array::GenericArray::from_slice(crypto.cipher.params.iv.as_bytes()),
    );
    aes_cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(
        "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑",
        "7465737470617373776f7264f09f9491"
        ; "eip2335_nfkd_vector"
    )]
    #[test_case(
        "a\u{0000}b\u{001f}c d\u{007f}e\u{0080}f\u{009f}g",
        "6162632064656667"
        ; "strip_c0_c1_del_keep_space"
    )]
    fn password_normalization_vectors(password: &str, expected_hex: &str) {
        let normalized = normalize_password(password);
        assert_eq!(hex::encode(normalized.as_slice()), expected_hex);
    }

    #[test]
    fn eip2335_scrypt_vector_checksum_and_cipher() {
        // From EIP-2335 "Scrypt Test Vector".
        let keystore = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
                }
            },
            "description": "This is a test keystore that uses scrypt to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/3141592653/589793238",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "version": 4
        }
        "#;
        let store: crate::keystore::store::Keystore = serde_json::from_str(keystore).unwrap();
        let password = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";

        // Verify checksum construction matches spec: SHA256(DK[16:32] ||
        // cipher.message).
        let normalized = normalize_password(password);
        let dk = derive_key(&store.crypto.kdf.params, &normalized).unwrap();
        let computed = generate_checksum(&dk, store.crypto.cipher.message.as_bytes());
        assert_eq!(
            computed.as_slice(),
            store.crypto.checksum.message.as_bytes()
        );

        // Verify AES-128-CTR decryption matches spec.
        let plaintext = decrypt(&store.crypto, password).unwrap();
        let expected =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        assert_eq!(plaintext, expected);
    }

    #[test]
    fn eip2335_pbkdf2_vector_checksum_and_cipher() {
        // From EIP-2335 "PBKDF2 Test Vector".
        let keystore = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                }
            },
            "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
            "version": 4
        }
        "#;
        let store: crate::keystore::store::Keystore = serde_json::from_str(keystore).unwrap();
        let password = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";

        // Verify checksum construction matches spec: SHA256(DK[16:32] ||
        // cipher.message).
        let normalized = normalize_password(password);
        let dk = derive_key(&store.crypto.kdf.params, &normalized).unwrap();
        let computed = generate_checksum(&dk, store.crypto.cipher.message.as_bytes());
        assert_eq!(
            computed.as_slice(),
            store.crypto.checksum.message.as_bytes()
        );

        // Verify AES-128-CTR decryption matches spec.
        let plaintext = decrypt(&store.crypto, password).unwrap();
        let expected =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        assert_eq!(plaintext, expected);
    }

    #[test]
    fn encrypt_rejects_zero_cost() {
        let secret = [0u8; 32];
        let result = encrypt(&secret, "test", Some(0), &mut rand::thread_rng());
        assert!(matches!(result, Err(KeystoreError::InvalidPbkdf2Param)));
    }

    #[test]
    fn encrypt_good() {
        let secret = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let password = "wallet passphrase";

        let crypto = encrypt(&secret, password, Some(1024), &mut rand::thread_rng()).unwrap();
        let decrypted = decrypt(&crypto, password).unwrap();

        assert_eq!(secret.as_slice(), decrypted.as_slice());
    }

    #[test_case([0u8; 32], "" ; "empty password")]
    #[test_case([0x42u8; 32], "test" ; "normal input")]
    fn encrypt_valid(secret: [u8; 32], password: &str) {
        let result = encrypt(&secret, password, Some(1024), &mut rand::thread_rng());
        assert!(result.is_ok());
    }

    // ========== Decryption tests (from decrypt_test.go) ==========

    #[test_case(
        r#"{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"#,
        "testpassword",
        vec![0x11, 0xdd, 0x0c, 0x87, 0xfe, 0xf7, 0x48, 0xdc, 0x07, 0xee, 0xb7, 0x0e, 0x0d, 0xe5, 0xdc, 0x94, 0x4c, 0xd4, 0xd5, 0xbe, 0x86, 0x4e, 0x0c, 0x40, 0x35, 0x26, 0xf2, 0xfd, 0x34, 0x61, 0xa8, 0x3e]
        ; "pbkdf2 with ascii password"
    )]
    #[test_case(
        r#"{"checksum":{"function":"sha256","message":"3e1d45e3e47bcb2406ab25b6119225c85e7b2276b0834c7203a125bd7b6ca34f","params":{}},"cipher":{"function":"aes-128-ctr","message":"0ed64a392274f7fcc76f8cf4d22f86057c42e6c6b726cc19dc64e80ebab5d1dd","params":{"iv":"ff6cc499ff4bbfca0125700b29cfa4dc"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"70f3ebd9776781f46c2ead400a3a9ed7ad2880871fe9422a734303d1492f2477"}}}"#,
        "testpassword\u{00fc}",
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
        let crypto: Crypto = serde_json::from_str(input).unwrap();
        let output = decrypt(&crypto, passphrase).unwrap();
        assert_eq!(expected, output);
    }

    #[test_case(
        r#"{"checksum":{"function":"sha256","message":"0ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"#,
        "testpassword"
        ; "invalid checksum"
    )]
    fn decrypt_should_fail(input: &str, passphrase: &str) {
        let crypto: Crypto = serde_json::from_str(input).unwrap();
        let result = decrypt(&crypto, passphrase);
        assert!(matches!(result, Err(KeystoreError::InvalidChecksum)));
    }

    #[test_case(r#"{"checksum":{"function":"sha256","message":"hb9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"# ; "bad checksum message")]
    #[test_case(r#"{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"h12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"# ; "bad cipher message")]
    #[test_case(r#"{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"h29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"# ; "bad iv")]
    #[test_case(r#"{"checksum":{"function":"sha256","message":"9ca5a58a8a8d7a62c3bd890c51ab3169bcfd7f154947458ac4f2950b059b6b38","params":{}},"cipher":{"function":"aes-128-ctr","message":"12edd28c7290896ea24ecda9066f34a70dbab972d8d975f5727f938ba5a8641f","params":{"iv":"b29d49568661b61e92352e3bb36038d9"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"hbd90262ceea3018400076177f5bc55b6e185d5e63361bebdda4a2f7a2066caadc"}}}"# ; "bad salt")]
    fn decrypt_invalid_json(input: &str) {
        let result = serde_json::from_str::<Crypto>(input);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let secret = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let password = "testpassword";

        // Use low cost for fast testing
        let crypto = encrypt(secret, password, Some(16), &mut rand::thread_rng()).unwrap();
        let decrypted = decrypt(&crypto, password).unwrap();

        assert_eq!(secret.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn decrypt_wrong_password() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let password = "correctpassword";

        let crypto = encrypt(secret, password, Some(16), &mut rand::thread_rng()).unwrap();
        let result = decrypt(&crypto, "wrongpassword");

        assert!(matches!(result, Err(KeystoreError::InvalidChecksum)));
    }

    // ========== Strictness tests (Lighthouse-style: reject at deserialize)
    // ==========

    #[test]
    fn deserialize_rejects_unknown_fields_in_crypto() {
        let json = r#"{"extra":1,"checksum":{"function":"sha256","message":"aa","params":{}},"cipher":{"function":"aes-128-ctr","message":"bb","params":{"iv":"cc"}},"kdf":{"function":"pbkdf2","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"dd"},"message":""}}"#;
        assert!(serde_json::from_str::<Crypto>(json).is_err());
    }

    #[test]
    fn deserialize_rejects_unknown_fields_in_cipher_params() {
        let json = r#"{"checksum":{"function":"sha256","message":"aa","params":{}},"cipher":{"function":"aes-128-ctr","message":"bb","params":{"iv":"cc","extra":1}},"kdf":{"function":"pbkdf2","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"dd"},"message":""}}"#;
        assert!(serde_json::from_str::<Crypto>(json).is_err());
    }

    #[test]
    fn deserialize_rejects_non_empty_checksum_params() {
        let json = r#"{"checksum":{"function":"sha256","message":"aa","params":{"x":1}},"cipher":{"function":"aes-128-ctr","message":"bb","params":{"iv":"cc"}},"kdf":{"function":"pbkdf2","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"dd"},"message":""}}"#;
        assert!(serde_json::from_str::<Crypto>(json).is_err());
    }

    #[test]
    fn deserialize_rejects_non_empty_kdf_message() {
        let json = r#"{"checksum":{"function":"sha256","message":"aa","params":{}},"cipher":{"function":"aes-128-ctr","message":"bb","params":{"iv":"cc"}},"kdf":{"function":"pbkdf2","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"dd"},"message":"x"}}"#;
        assert!(serde_json::from_str::<Crypto>(json).is_err());
    }

    #[test]
    fn decrypt_rejects_pbkdf2_c_zero() {
        let json = r#"{"checksum":{"function":"sha256","message":"aa","params":{}},"cipher":{"function":"aes-128-ctr","message":"bb","params":{"iv":"cc"}},"kdf":{"function":"pbkdf2","params":{"c":0,"dklen":32,"prf":"hmac-sha256","salt":"dd"},"message":""}}"#;
        let crypto: Crypto = serde_json::from_str(json).unwrap();
        let err = decrypt(&crypto, "pw").unwrap_err();
        assert!(matches!(err, KeystoreError::InvalidPbkdf2Param));
    }
}
