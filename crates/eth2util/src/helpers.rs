use std::{collections::HashMap, sync::LazyLock};

use alloy::primitives::Address;
use k256::{PublicKey, elliptic_curve::sec1::ToEncodedPoint};
use regex::Regex;

// The pattern ([^=,]+) captures any string that does not contain '=' or ','.
// The pattern ([^,]+) captures any string that does not contain ','.
// The composition of patterns ([^=,]+)=([^,]+) captures a pair of header and
// its corresponding value. We use ^ at the start and $ at the end to ensure
// exact match.
static HEADER_PATTERN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([^=,]+)=([^,]+)$").expect("invalid regex"));

/// Error type for helper operations
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// Invalid Ethereum address format
    #[error("Invalid ethereum address: {0}")]
    InvalidAddress(String),

    /// Hex decoding error
    #[error("Invalid ethereum hex address: {0}")]
    InvalidHexAddress(String),

    /// Invalid HTTP header format
    #[error("HTTP headers must be comma separated values formatted as header=value")]
    InvalidHTTPHeader,

    /// Failed to get the beacon node spec
    #[error("getting spec: {0}")]
    GettingSpec(String),

    /// Failed to fetch a required value from the spec
    #[error("fetch slots per epoch")]
    FetchSlotsPerEpoch,
}

type Result<T> = std::result::Result<T, HelperError>;

/// Validates the format of HTTP headers.
pub fn validate_http_headers(headers: &[String]) -> Result<()> {
    if headers.is_empty() {
        return Ok(());
    }

    for header in headers {
        if !HEADER_PATTERN_RE.is_match(header) {
            return Err(HelperError::InvalidHTTPHeader);
        }
    }

    Ok(())
}

/// Validates and parses HTTP headers into a map of key-value pairs.
/// Returns empty map if headers is empty.
pub fn parse_http_headers(headers: &[String]) -> Result<HashMap<String, String>> {
    let mut parsed_headers = HashMap::new();

    if headers.is_empty() {
        return Ok(parsed_headers);
    }

    validate_http_headers(headers)?;

    for header in headers {
        let parts: Vec<&str> = header.splitn(2, '=').collect();
        if parts.len() == 2 {
            parsed_headers.insert(parts[0].to_string(), parts[1].to_string());
        }
    }

    Ok(parsed_headers)
}

/// Returns an EIP55-compliant checksummed address.
pub fn checksum_address(address: impl AsRef<str>) -> Result<String> {
    let addr = verify_address(address.as_ref())?;
    Ok(addr.to_checksum(None))
}

/// Returns the EIP55-compliant 0xhex ethereum address of the public key.
pub fn public_key_to_address(pubkey: &PublicKey) -> String {
    // Alloy expects the 64-byte uncompressed public key without the 0x04 prefix
    let uncompressed = pubkey.to_encoded_point(false);
    let uncompressed_bytes = uncompressed.as_bytes();

    // Skip the first byte (0x04 prefix) and pass the 64-byte key to Alloy
    Address::from_raw_public_key(&uncompressed_bytes[1..]).to_checksum(None)
}

pub(crate) fn verify_address(address: &str) -> Result<Address> {
    // Validate that address starts with "0x"
    if !address.starts_with("0x") {
        return Err(HelperError::InvalidAddress(address.to_string()));
    }

    address
        .parse()
        .map_err(|_| HelperError::InvalidAddress(address.to_string()))
}

/// Returns epoch calculated from given slot.
pub async fn epoch_from_slot(
    client: &pluto_eth2api::client::EthBeaconNodeApiClient,
    slot: u64,
) -> Result<u64> {
    let resp = match client
        .get_spec(pluto_eth2api::GetSpecRequest {})
        .await
        .map_err(|e| HelperError::GettingSpec(e.to_string()))?
    {
        pluto_eth2api::GetSpecResponse::Ok(resp) => resp,
        pluto_eth2api::GetSpecResponse::InternalServerError(err) => {
            return Err(HelperError::GettingSpec(err.message));
        }
        pluto_eth2api::GetSpecResponse::Unknown => {
            return Err(HelperError::GettingSpec("unknown response".into()));
        }
    };

    let slots_per_epoch: u64 = resp
        .data
        .as_object()
        .and_then(|obj| obj.get("SLOTS_PER_EPOCH"))
        .and_then(|v| v.as_str())
        .ok_or(HelperError::FetchSlotsPerEpoch)?
        .parse()
        .map_err(|_| HelperError::FetchSlotsPerEpoch)?;

    slot.checked_div(slots_per_epoch)
        .ok_or(HelperError::FetchSlotsPerEpoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::SecretKey;

    #[test]
    fn test_checksummed_address() {
        // Test examples from https://eips.ethereum.org/EIPS/eip-55.
        let addrs = vec![
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ];

        for addr in addrs {
            // Test with correctly checksummed address
            let checksummed = checksum_address(addr).unwrap();
            assert_eq!(addr, checksummed);

            // Test with lowercase address
            let checksummed = checksum_address(addr.to_lowercase()).unwrap();
            assert_eq!(addr, checksummed);

            // Test with uppercase address (0x + uppercase hex)
            let uppercase_addr = format!("0x{}", &addr[2..].to_uppercase());
            let checksummed = checksum_address(&uppercase_addr).unwrap();
            assert_eq!(addr, checksummed);
        }
    }

    #[test]
    fn test_invalid_addrs() {
        let addrs = vec![
            "0x0000000000000000000000000000000000dead",
            "0x00000000000000000000000000000000000000dead",
            "0x0000000000000000000000000000000000000bar",
            "000000000000000000000000000000000000dead",
        ];

        for addr in addrs {
            let result = checksum_address(addr);
            assert!(result.is_err(), "Expected error for address: {}", addr);
        }
    }

    #[test]
    fn test_public_key_to_address() {
        // Test fixtures from geth/crypto package.
        const TEST_ADDR_HEX: &str = "0x970E8128AB834E8EAC17Ab8E3812F010678CF791";
        const TEST_PRIV_HEX: &str =
            "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032";

        let priv_bytes = hex::decode(TEST_PRIV_HEX).unwrap();
        let secret_key = SecretKey::from_slice(&priv_bytes).unwrap();
        let public_key = secret_key.public_key();

        let actual = public_key_to_address(&public_key);
        assert_eq!(TEST_ADDR_HEX, actual);
    }

    #[test]
    fn test_validate_http_headers() {
        struct TestCase {
            name: &'static str,
            headers: Vec<String>,
            valid: bool,
        }

        let tests = vec![
            TestCase {
                name: "nil",
                headers: vec![],
                valid: true,
            },
            TestCase {
                name: "one pair",
                headers: vec!["header-1=value-1".to_string()],
                valid: true,
            },
            TestCase {
                name: "two pairs",
                headers: vec![
                    "header-1=value-1".to_string(),
                    "header-2=value-2".to_string(),
                ],
                valid: true,
            },
            TestCase {
                name: "empty",
                headers: vec!["".to_string()],
                valid: false,
            },
            TestCase {
                name: "value missing",
                headers: vec!["header-1=".to_string()],
                valid: false,
            },
            TestCase {
                name: "header missing",
                headers: vec!["=value-1".to_string()],
                valid: false,
            },
            TestCase {
                name: "extra comma end",
                headers: vec!["header-1=value-1,".to_string()],
                valid: false,
            },
            TestCase {
                name: "extra comma start",
                headers: vec![",header-1=value-1".to_string()],
                valid: false,
            },
            TestCase {
                name: "pair and value missing",
                headers: vec!["header-1=value-1".to_string(), "header-2=".to_string()],
                valid: false,
            },
            TestCase {
                name: "header and value missing 1",
                headers: vec!["==".to_string()],
                valid: false,
            },
            TestCase {
                name: "header and value missing 2",
                headers: vec![",,".to_string()],
                valid: false,
            },
            TestCase {
                name: "value contains equal sign",
                headers: vec!["Authorization=Basic bmljZXRyeQ==".to_string()],
                valid: true,
            },
        ];

        for tt in tests {
            let err = validate_http_headers(&tt.headers);
            if err.is_err() && tt.valid {
                panic!(
                    "Test '{}': Header ({:?}) is invalid, want valid",
                    tt.name, tt.headers
                );
            } else if err.is_ok() && !tt.valid {
                panic!(
                    "Test '{}': Header ({:?}) is valid, want invalid",
                    tt.name, tt.headers
                );
            }
        }
    }

    #[test]
    fn test_parse_http_headers() {
        struct TestCase {
            name: &'static str,
            headers: Vec<String>,
            want: HashMap<String, String>,
        }

        let tests = vec![
            TestCase {
                name: "nil",
                headers: vec![],
                want: HashMap::new(),
            },
            TestCase {
                name: "one pair",
                headers: vec!["header-1=value-1".to_string()],
                want: {
                    let mut m = HashMap::new();
                    m.insert("header-1".to_string(), "value-1".to_string());
                    m
                },
            },
            TestCase {
                name: "two pairs",
                headers: vec![
                    "header-1=value-1".to_string(),
                    "header-2=value-2".to_string(),
                ],
                want: {
                    let mut m = HashMap::new();
                    m.insert("header-1".to_string(), "value-1".to_string());
                    m.insert("header-2".to_string(), "value-2".to_string());
                    m
                },
            },
            TestCase {
                name: "value contains equal sign",
                headers: vec!["Authorization=Basic bmljZXRyeQ==".to_string()],
                want: {
                    let mut m = HashMap::new();
                    m.insert(
                        "Authorization".to_string(),
                        "Basic bmljZXRyeQ==".to_string(),
                    );
                    m
                },
            },
        ];

        for tt in tests {
            let parsed = parse_http_headers(&tt.headers);
            if parsed.is_err() {
                panic!(
                    "Test '{}': Header ({:?}) failed to parse",
                    tt.name, tt.headers
                );
            }

            let parsed = parsed.unwrap();
            if parsed != tt.want {
                panic!(
                    "Test '{}': Headers badly parsed, have {:?}, want {:?}",
                    tt.name, parsed, tt.want
                );
            }
        }
    }
}
