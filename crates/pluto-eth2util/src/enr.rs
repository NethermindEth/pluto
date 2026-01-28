use std::{collections::HashMap, fmt::Display, net::Ipv4Addr};

use base64::Engine;
use k256::{PublicKey, SecretKey, elliptic_curve};
use pluto_k1util::{self, SIGNATURE_LEN_WITHOUT_V};
use sha3::{Digest, Keccak256};

use crate::{
    rlp::{RlpError, decode_bytes_list, encode_bytes_list},
    utils,
};

/// The key for the secp256k1 public key in the ENR.
pub const KEY_SECP256K1: &str = "secp256k1";
/// The key for the node ID in the ENR.
pub const KEY_ID: &str = "id";
/// The value for the node ID in the ENR.
pub const VAL_ID: &str = "v4";
/// The key for the IP address in the ENR.
pub const KEY_IP: &str = "ip";
/// The key for the TCP port in the ENR.
pub const KEY_TCP: &str = "tcp";
/// The key for the UDP port in the ENR.
pub const KEY_UDP: &str = "udp";

/// An error that can occur when parsing an ENR record.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The format of the record is invalid.
    #[error("The format of the record is invalid: {0}")]
    InvalidFormat(#[from] InvalidFormatError),

    /// The record is too short.
    #[error("The record is too short: expected {expected}, actual {actual}")]
    TooShort {
        /// The expected length.
        expected: usize,
        /// The actual length.
        actual: usize,
    },

    /// Duplicate key found in ENR record.
    #[error("Duplicate key found in ENR record: {0}")]
    DuplicateKey(String),

    /// Failed to decode the base64 encoded data.
    #[error("Failed to decode the base64 encoded data: {0}")]
    FailedToDecodeBase64(#[from] base64::DecodeError),

    /// Failed to decode the RLP encoded data.
    #[error("Failed to decode the RLP encoded data: {0}")]
    FailedToDecodeRlp(#[from] RlpError),

    /// Failed to parse the secp256k1 public key.
    #[error("Failed to parse the secp256k1 public key: {0}")]
    Secp256k1Error(#[from] elliptic_curve::Error),

    /// Failed to verify the signature.
    #[error("Signature verification succeeded, but the signature is invalid")]
    FailedToVerifySignature,

    /// The signature is invalid.
    #[error("The verification failed: {0}")]
    InvalidSignature(pluto_k1util::K1UtilError),

    /// Failed to sign the record.
    #[error("Failed to sign the record: {0}")]
    FailedToSign(pluto_k1util::K1UtilError),

    /// Failed to convert the signature.
    #[error("Failed to convert the signature: {0}")]
    FailedToConvertSignature(std::array::TryFromSliceError),
}

/// InvalidFormatError is an error type for invalid format errors.
#[derive(Debug, thiserror::Error)]
pub enum InvalidFormatError {
    /// Record does not start with 'enr:'.
    #[error("Record does not start with 'enr:'")]
    DoesNotStartWithEnr,

    /// Invalid enr record, odd number of elements.
    #[error("Invalid enr record, odd number of elements")]
    OddNumberOfElements,

    /// Non-v4 identity scheme not supported.
    #[error("Non-v4 identity scheme not supported")]
    NonV4IdentitySchemeNotSupported,

    /// Public key is not set.
    #[error("Public key is not set")]
    PublicKeyNotSet,
}

/// A record in the ENR.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Record {
    /// The public key of the record.
    pub public_key: Option<PublicKey>,

    /// The signature of the record.
    pub signature: Vec<u8>,

    /// The key-value pairs of the record.
    kvs: HashMap<String, Vec<u8>>,
}

/// OptionFn is a function that sets an option in the record.
pub type OptionFn = Box<dyn Fn(&mut HashMap<String, Vec<u8>>)>;

/// with_ip_impl is a function that sets the IP address in the record.
pub fn with_ip_impl(ip: Ipv4Addr) -> OptionFn {
    Box::new(move |kvs: &mut HashMap<String, Vec<u8>>| {
        kvs.insert(KEY_IP.to_string(), ip.octets().to_vec());
    })
}

/// with_tcp_impl is a function that sets the TCP port in the record.
pub fn with_tcp_impl(tcp: u16) -> OptionFn {
    Box::new(move |kvs: &mut HashMap<String, Vec<u8>>| {
        kvs.insert(KEY_TCP.to_string(), tcp.to_be_bytes().to_vec());
    })
}

/// with_udp_impl is a function that sets the UDP port in the record.
pub fn with_udp_impl(udp: u16) -> OptionFn {
    Box::new(move |kvs: &mut HashMap<String, Vec<u8>>| {
        kvs.insert(KEY_UDP.to_string(), udp.to_be_bytes().to_vec());
    })
}

impl Record {
    /// Creates a new record.
    pub fn new(secret_key: SecretKey, opts: Vec<OptionFn>) -> Result<Self, RecordError> {
        let mut kvs: HashMap<String, Vec<u8>> = HashMap::new();

        kvs.insert(KEY_ID.to_string(), VAL_ID.as_bytes().to_vec());
        kvs.insert(
            KEY_SECP256K1.to_string(),
            secret_key.public_key().to_sec1_bytes().to_vec(),
        );

        for opt in opts {
            opt(&mut kvs);
        }

        let signature = sign(&secret_key, &encode_elements(&[], &kvs))?;

        Ok(Record {
            public_key: Some(secret_key.public_key()),
            signature: signature.to_vec(),
            kvs,
        })
    }

    /// Returns the IP address of the record.
    ///
    /// Returns None if the IP address is not set.
    pub fn ip(&self) -> Option<Ipv4Addr> {
        let value = self.kvs.get(KEY_IP)?;
        let bytes: [u8; 4] = value.as_slice().try_into().ok()?;
        Some(Ipv4Addr::from(bytes))
    }

    /// Returns the TCP port of the record.
    ///
    /// Returns None if the TCP port is not set.
    pub fn tcp(&self) -> Option<u16> {
        let value = self.kvs.get(KEY_TCP)?;
        let bytes = value.as_slice().try_into().ok()?;
        Some(u16::from_be_bytes(bytes))
    }

    /// Returns the UDP port of the record.
    ///
    /// Returns None if the UDP port is not set.
    pub fn udp(&self) -> Option<u16> {
        let value = self.kvs.get(KEY_UDP)?;
        let bytes = value.as_slice().try_into().ok()?;
        Some(u16::from_be_bytes(bytes))
    }
}

impl Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        write!(
            f,
            "enr:{}",
            engine.encode(encode_elements(&self.signature, &self.kvs))
        )
    }
}

impl TryFrom<&str> for Record {
    type Error = RecordError;

    fn try_from(enr_str: &str) -> Result<Self, Self::Error> {
        if !enr_str.starts_with("enr:") {
            return Err(RecordError::InvalidFormat(
                InvalidFormatError::DoesNotStartWithEnr,
            ));
        }

        // Ensure backwards compatibility with older versions with encoded ENR strings.
        // ENR strings in older versions of charon (<= v0.9.0) were base64 padded
        // strings with "=" as the padding character. Refer: https://github.com/ObolNetwork/charon/issues/970
        let enr_str = enr_str.trim_end_matches('=');
        let enr_str = enr_str.strip_prefix("enr:").unwrap_or(enr_str);

        let base64_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let raw = base64_engine
            .decode(enr_str)
            .map_err(RecordError::FailedToDecodeBase64)?;

        let elements = decode_bytes_list(&raw)?;

        if elements.len() < 4 {
            return Err(RecordError::TooShort {
                expected: 4,
                actual: elements.len(),
            });
        }

        if elements.len() % 2 != 0 {
            return Err(RecordError::InvalidFormat(
                InvalidFormatError::OddNumberOfElements,
            ));
        }

        let mut record = Record {
            signature: elements[0].clone(),
            public_key: None,
            kvs: HashMap::new(),
        };

        for pair in elements.chunks_exact(2).skip(1) {
            let [key, value] = pair else {
                unreachable!("Expected even number of elements");
            };
            let key = String::from_utf8_lossy(key).to_string();

            if record.kvs.contains_key(&key) {
                return Err(RecordError::DuplicateKey(key));
            }

            record.kvs.insert(key.clone(), value.clone());

            match key.as_str() {
                KEY_SECP256K1 => {
                    record.public_key = Some(
                        PublicKey::from_sec1_bytes(value).map_err(RecordError::Secp256k1Error)?,
                    );
                }
                KEY_ID => {
                    let value_str = String::from_utf8_lossy(value).to_string();
                    if value_str != VAL_ID {
                        return Err(RecordError::InvalidFormat(
                            InvalidFormatError::NonV4IdentitySchemeNotSupported,
                        ));
                    }
                }
                _ => {}
            }
        }

        let Some(public_key) = record.public_key else {
            return Err(RecordError::InvalidFormat(
                InvalidFormatError::PublicKeyNotSet,
            ));
        };

        let encoded_elements = encode_bytes_list(&elements[1..]);

        verify(&public_key, &record.signature, &encoded_elements)?;

        Ok(record)
    }
}

// sign returns a enr record signature.
pub(crate) fn sign(
    private_key: &SecretKey,
    raw_excl_sig: &[u8],
) -> Result<[u8; SIGNATURE_LEN_WITHOUT_V], RecordError> {
    let mut hasher = Keccak256::new();
    hasher.update(raw_excl_sig);
    let digest = hasher.finalize();

    let signature = pluto_k1util::sign(private_key, &digest).map_err(RecordError::FailedToSign)?;
    let signature_without_v = signature[..SIGNATURE_LEN_WITHOUT_V]
        .try_into()
        .expect("SIGNATURE_LEN_WITHOUT_V < SIGNATURE_LEN");

    Ok(signature_without_v)
}

// verify return an error if the record signature verification fails.
pub(crate) fn verify(
    pubkey: &PublicKey,
    signature: &[u8],
    raw_excl_sig: &[u8],
) -> Result<(), RecordError> {
    let mut hasher = Keccak256::new();
    hasher.update(raw_excl_sig);
    let digest = hasher.finalize();

    match pluto_k1util::verify_64(pubkey, &digest, signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(RecordError::FailedToVerifySignature),
        Err(e) => Err(RecordError::InvalidSignature(e)),
    }
}

pub(crate) fn encode_elements(signature: &[u8], kvs: &HashMap<String, Vec<u8>>) -> Vec<u8> {
    let mut keys: Vec<&String> = kvs.keys().collect();
    keys.sort();

    // Start with sequence number = 0
    let mut elements: Vec<Vec<u8>> = vec![utils::to_big_endian(0)];

    for key in keys {
        elements.push(key.as_bytes().to_vec());
        elements.push(kvs[key].clone());
    }

    if !signature.is_empty() {
        elements.insert(0, signature.to_vec());
    }

    encode_bytes_list(&elements)
}

#[cfg(test)]
mod tests {
    use crate::utils;
    use charon_testutil::random::generate_insecure_k1_key;
    use k256::{
        Secp256k1,
        elliptic_curve::{SecretKey, rand_core::OsRng},
    };

    use super::*;

    #[test]
    fn test_parse() {
        let r = Record::try_from("enr:-Iu4QJyserRukhG0Vgi2csu7GjpHYUGufNEbZ8Q7ZBrcZUb0KqpL5QzHonkh1xxHlxatTxrIcX_IS5J3SEWR_sa0ptGAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMAUgEqczOjevyculnUIofhCj0DkgJudErM7qCYIvIkzIN0Y3CCDhqDdWRwgg4u").unwrap();

        let pk = r.public_key.expect("Public key should be set");
        assert_eq!(
            pk.to_sec1_bytes().to_vec(),
            hex::decode("030052012a7333a37afc9cba59d42287e10a3d0392026e744acceea09822f224cc")
                .unwrap()
        );

        let ip = r.ip().expect("IP address should be set");
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));

        let tcp = r.tcp().expect("TCP port should be set");
        assert_eq!(tcp, 3610);

        let udp = r.udp().expect("UDP port should be set");
        assert_eq!(udp, 3630);
    }

    #[test]
    fn test_encode_decode() {
        let secret_key: SecretKey<Secp256k1> = SecretKey::random(&mut OsRng);

        let r1 = Record::new(secret_key, vec![]).expect("Failed to create record");

        let r2 = Record::try_from(r1.to_string().as_str()).expect("Failed to parse record");

        assert_eq!(r1, r2);

        assert!(r1.ip().is_none());
        assert!(r1.tcp().is_none());
    }

    #[test]
    fn test_ip_tcp() {
        let secret_key: SecretKey<Secp256k1> = SecretKey::random(&mut OsRng);

        let expect_ip = Ipv4Addr::new(1, 2, 3, 4);
        let expect_tcp = 8000;
        let expect_udp = 9000;

        let r1 = Record::new(
            secret_key,
            vec![
                with_ip_impl(expect_ip),
                with_tcp_impl(expect_tcp),
                with_udp_impl(expect_udp),
            ],
        )
        .expect("Failed to create record");

        let ip = r1.ip().expect("IP address should be set");
        assert_eq!(ip, expect_ip);

        let tcp = r1.tcp().expect("TCP port should be set");
        assert_eq!(tcp, expect_tcp);

        let udp = r1.udp().expect("UDP port should be set");
        assert_eq!(udp, expect_udp);

        let r2 = Record::try_from(r1.to_string().as_str()).expect("Failed to parse record");

        assert_eq!(r1, r2);

        let ip = r2.ip().expect("IP address should be set");
        assert_eq!(ip, expect_ip);

        let tcp = r2.tcp().expect("TCP port should be set");
        assert_eq!(tcp, expect_tcp);

        let udp = r2.udp().expect("UDP port should be set");
        assert_eq!(udp, expect_udp);
    }

    #[test]
    fn test_new() {
        let secret_key: SecretKey<Secp256k1> = generate_insecure_k1_key(0);

        let r = Record::new(secret_key, vec![]).expect("Failed to create record");

        assert_eq!(
            r.to_string(),
            "enr:-HW4QEp-BLhP30tqTGFbR9n2PdUKWP9qc0zphIRmn8_jpm4BYkgekztXQaPA_znRW8RvNYHo0pUwyPEwUGGeZu26XlKAgmlkgnY0iXNlY3AyNTZrMaEDG4TFVnsSZECZXT7VqroFZdceGDRgSBn_nBf16dXdB48"
        );
    }

    mod duplicate_keys {
        use super::*;

        struct DuplicateKeys {
            kvs: HashMap<String, Vec<u8>>,
        }

        impl DuplicateKeys {
            fn new(kvs: HashMap<String, Vec<u8>>) -> Self {
                let mut kvs = kvs;
                kvs.insert(KEY_ID.to_string(), VAL_ID.as_bytes().to_vec());
                kvs.insert(KEY_IP.to_string(), "127.0.0.1".as_bytes().to_vec());
                kvs.insert(KEY_TCP.to_string(), "3610".as_bytes().to_vec());
                kvs.insert(KEY_UDP.to_string(), "3630".as_bytes().to_vec());
                Self { kvs }
            }
        }

        impl Display for DuplicateKeys {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                write!(
                    f,
                    "enr:{}",
                    engine.encode(encode_elements_duplicate_keys(&self.kvs))
                )
            }
        }

        fn encode_elements_duplicate_keys(kvs: &HashMap<String, Vec<u8>>) -> Vec<u8> {
            let mut keys: Vec<&String> = kvs.keys().collect();
            keys.sort();

            // Start with sequence number = 0
            let mut elements: Vec<Vec<u8>> = vec![utils::to_big_endian(0), utils::to_big_endian(0)];

            for key in keys {
                elements.push(key.as_bytes().to_vec());
                elements.push(kvs[key].clone());

                elements.push(key.as_bytes().to_vec());
                elements.push(kvs[key].clone());
            }

            encode_bytes_list(&elements)
        }

        #[test]
        fn test_duplicate_keys() {
            let kvs = DuplicateKeys::new(HashMap::new());
            let r = Record::try_from(kvs.to_string().as_str())
                .expect_err("Should fail to parse record");
            assert_eq!(
                r.to_string(),
                RecordError::DuplicateKey(KEY_ID.to_string()).to_string()
            );
        }
    }
}
