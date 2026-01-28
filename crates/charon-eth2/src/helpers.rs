use std::{collections::HashMap, sync::LazyLock};

use k256::{PublicKey, elliptic_curve::sec1::ToEncodedPoint};
use regex::Regex;
use sha3::{Digest, Keccak256};

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
pub fn checksum_address(address: &str) -> Result<String> {
    // Validate format: must have "0x" prefix and be exactly 42 chars (0x + 40 hex
    // chars)
    if !address.starts_with("0x") || address.len() != 2 + 20 * 2 {
        return Err(HelperError::InvalidAddress(address.to_string()));
    }

    let bytes = hex::decode(&address[2..])
        .map_err(|e| HelperError::InvalidHexAddress(format!("{}: {}", address, e)))?;

    Ok(checksum_address_bytes(&bytes))
}

/// Returns an EIP55-compliant 0xhex representation of the binary ethereum
/// address.
pub fn checksum_address_bytes(address_bytes: &[u8]) -> String {
    let hex_addr = hex::encode(address_bytes);

    let hash = Keccak256::digest(hex_addr.as_bytes());
    let hex_hash = hex::encode(hash);

    let mut result = String::from("0x");

    for (i, c) in hex_addr.chars().enumerate() {
        if c > '9' && hex_hash.as_bytes()[i] > b'7' {
            result.push(c.to_ascii_uppercase());
        } else {
            result.push(c);
        }
    }

    result
}

/// Returns the EIP55-compliant 0xhex ethereum address of the public key.
pub fn public_key_to_address(pubkey: &PublicKey) -> String {
    let uncompressed = pubkey.to_encoded_point(false);
    let uncompressed_bytes = uncompressed.as_bytes();
    let hash = Keccak256::digest(&uncompressed_bytes[1..]);

    checksum_address_bytes(&hash[12..])
}

// TODO: missing EpochFromSlot https://github.com/ObolNetwork/charon/blob/v1.7.1/eth2util/helpers.go#L62

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
            let checksummed = checksum_address(&addr.to_lowercase()).unwrap();
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
