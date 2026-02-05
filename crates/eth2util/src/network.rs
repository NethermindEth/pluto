use chrono::{DateTime, Utc};
use std::sync::{LazyLock, RwLock};

/// Prater
pub const PRATER: &str = "prater";

/// Network error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NetworkError {
    /// Network not found.
    #[error("Invalid network name: {name}")]
    InvalidName {
        /// The invalid network name.
        name: String,
    },

    /// Invalid fork version.
    #[error("Invalid fork version: {fork_version}")]
    InvalidForkVersion {
        /// The invalid fork version.
        fork_version: String,
    },

    /// Invalid genesis timestamp.
    #[error("Invalid genesis timestamp: {genesis_timestamp}")]
    InvalidGenesisTimestamp {
        /// The invalid genesis timestamp.
        genesis_timestamp: u64,
    },

    /// Failed to write to the supported networks.
    #[error("Failed to write to the supported networks")]
    FailedToWriteSupportedNetworks,

    /// Failed to read from the supported networks.
    #[error("Failed to read from the supported networks")]
    FailedToReadSupportedNetworks,
}

type Result<T> = std::result::Result<T, NetworkError>;

/// Network contains information about an Ethereum network.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Network {
    /// `chain_id` represents chain id of the network.
    pub chain_id: u64,
    /// name represents name of the network.
    pub name: &'static str,
    /// `genesis_fork_version_hex` represents fork version of the network in
    /// hex.
    pub genesis_fork_version_hex: &'static str,
    /// `genesis_timestamp` represents genesis timestamp of the network in unix
    /// format.
    pub genesis_timestamp: u64,
    /// `capella_hard_fork` represents capella fork version, used for computing
    /// domains for signatures.
    pub capella_hard_fork: &'static str,
}

impl Network {
    /// `is_non_zero` checks if each field in this struct is not equal to its
    /// zero value.
    #[must_use]
    pub fn is_non_zero(&self) -> bool {
        self != &Network::default()
    }
}

/// Pre-defined networks.
mod predefined {
    use super::Network;

    /// Mainnet network.
    pub const MAINNET: Network = Network {
        chain_id: 1,
        name: "mainnet",
        genesis_fork_version_hex: "0x00000000",
        genesis_timestamp: 1606824023,
        capella_hard_fork: "0x03000000",
    };

    /// Goerli network.
    pub const GOERLI: Network = Network {
        chain_id: 5,
        name: "goerli",
        genesis_fork_version_hex: "0x00001020",
        genesis_timestamp: 1616508000,
        capella_hard_fork: "0x03001020",
    };

    /// Gnosis network.
    pub const GNOSIS: Network = Network {
        chain_id: 100,
        name: "gnosis",
        genesis_fork_version_hex: "0x00000064",
        genesis_timestamp: 1638993340,
        capella_hard_fork: "0x03000064",
    };

    /// Chiado network.
    pub const CHIADO: Network = Network {
        chain_id: 10200,
        name: "chiado",
        genesis_fork_version_hex: "0x0000006f",
        genesis_timestamp: 1665396300,
        capella_hard_fork: "0x0300006f",
    };

    /// Sepolia network.
    pub const SEPOLIA: Network = Network {
        chain_id: 11155111,
        name: "sepolia",
        genesis_fork_version_hex: "0x90000069",
        genesis_timestamp: 1655733600,
        capella_hard_fork: "0x90000072",
    };

    /// Holesky network. Metadata taken from <https://github.com/eth-clients/holesky#metadata>.
    pub const HOLESKY: Network = Network {
        chain_id: 17000,
        name: "holesky",
        genesis_fork_version_hex: "0x01017000",
        genesis_timestamp: 1696000704,
        capella_hard_fork: "0x04017000",
    };

    /// Hoodi network. Metadata taken from <https://github.com/eth-clients/hoodi/#metadata>.
    pub const HOODI: Network = Network {
        chain_id: 560048,
        name: "hoodi",
        genesis_fork_version_hex: "0x10000910",
        genesis_timestamp: 1742213400,
        capella_hard_fork: "0x40000910",
    };
}

pub use predefined::*;

static SUPPORTED_NETWORKS: LazyLock<RwLock<Vec<Network>>> = LazyLock::new(|| {
    RwLock::new(vec![
        MAINNET, GOERLI, GNOSIS, CHIADO, SEPOLIA, HOLESKY, HOODI,
    ])
});

/// Add a test network to the supported networks.
pub fn add_test_network(network: Network) -> Result<()> {
    SUPPORTED_NETWORKS
        .write()
        .map_err(|_| NetworkError::FailedToWriteSupportedNetworks)?
        .push(network);
    Ok(())
}

/// Get the supported networks.
pub fn supported_networks() -> Result<Vec<Network>> {
    Ok(SUPPORTED_NETWORKS
        .read()
        .map_err(|_| NetworkError::FailedToReadSupportedNetworks)?
        .clone())
}

fn network_from_name(name: &str) -> Result<Network> {
    let networks = supported_networks()?;

    networks
        .iter()
        .find(|network| network.name == name)
        .ok_or(NetworkError::InvalidName {
            name: name.to_string(),
        })
        .cloned()
}

fn network_from_fork_version(fork_version: &str) -> Result<Network> {
    let networks = supported_networks()?;

    networks
        .iter()
        .find(|network| {
            network
                .genesis_fork_version_hex
                .strip_prefix("0x")
                .unwrap_or(network.genesis_fork_version_hex)
                == fork_version.strip_prefix("0x").unwrap_or(fork_version)
        })
        .ok_or(NetworkError::InvalidForkVersion {
            fork_version: fork_version.to_string(),
        })
        .cloned()
}

/// Fork version to chain ID.
pub fn fork_version_to_chain_id(fork_version: &[u8]) -> Result<u64> {
    let network = network_from_fork_version(hex::encode(fork_version).as_ref())?;
    Ok(network.chain_id)
}

/// Fork version to network.
pub fn fork_version_to_network(fork_version: &[u8]) -> Result<String> {
    let network = network_from_fork_version(hex::encode(fork_version).as_ref())?;
    Ok(network.name.to_string())
}

/// Network to fork version.
pub fn network_to_fork_version(network: &str) -> Result<String> {
    let network = network_from_name(network)?;
    Ok(network.genesis_fork_version_hex.to_string())
}

/// Network to fork version bytes.
pub fn network_to_fork_version_bytes(network: &str) -> Result<Vec<u8>> {
    let fork_version = network_to_fork_version(network)?;

    let b =
        hex::decode(fork_version.strip_prefix("0x").unwrap_or(&fork_version)).map_err(|_| {
            NetworkError::InvalidForkVersion {
                fork_version: fork_version.to_string(),
            }
        })?;

    Ok(b)
}

/// Valid network.
#[must_use]
pub fn valid_network(name: &str) -> bool {
    network_from_name(name).is_ok()
}

/// Network to genesis time.
pub fn network_to_genesis_time(name: &str) -> Result<DateTime<Utc>> {
    let network = network_from_name(name)?;
    DateTime::<Utc>::from_timestamp(
        i64::try_from(network.genesis_timestamp).map_err(|_| {
            NetworkError::InvalidGenesisTimestamp {
                genesis_timestamp: network.genesis_timestamp,
            }
        })?,
        0,
    )
    .ok_or(NetworkError::InvalidGenesisTimestamp {
        genesis_timestamp: network.genesis_timestamp,
    })
}

/// Fork version to genesis time.
pub fn fork_version_to_genesis_time(fork_version: &[u8]) -> Result<DateTime<Utc>> {
    let network = network_from_fork_version(hex::encode(fork_version).as_ref())?;
    network_to_genesis_time(network.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVALID_FORK_VERSION: &[u8] = &[1, 0, 1, 0];
    const INVALID_NETWORK: &str = "invalidNetwork";

    #[test]
    fn test_fork_version_to_chain_id() {
        let gnosis_fork_version = hex::decode(
            GNOSIS
                .genesis_fork_version_hex
                .strip_prefix("0x")
                .unwrap_or(GNOSIS.genesis_fork_version_hex),
        )
        .unwrap();

        let chain_id = fork_version_to_chain_id(&gnosis_fork_version).unwrap();

        assert_eq!(chain_id, GNOSIS.chain_id);
    }

    #[test]
    fn test_fork_version_to_network() {
        let sepolia_fork_version = hex::decode(
            SEPOLIA
                .genesis_fork_version_hex
                .strip_prefix("0x")
                .unwrap_or(SEPOLIA.genesis_fork_version_hex),
        )
        .unwrap();

        let network = fork_version_to_network(&sepolia_fork_version).unwrap();

        assert_eq!(network, SEPOLIA.name.to_string());

        let result = fork_version_to_network(INVALID_FORK_VERSION);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            NetworkError::InvalidForkVersion {
                fork_version: hex::encode(INVALID_FORK_VERSION),
            }
        );
    }

    #[test]
    fn test_network_to_fork_version() {
        let fv = network_to_fork_version(SEPOLIA.name).unwrap();
        assert_eq!(fv, SEPOLIA.genesis_fork_version_hex.to_string());

        let result = network_to_fork_version(INVALID_NETWORK);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            NetworkError::InvalidName {
                name: INVALID_NETWORK.to_string(),
            }
        );
    }

    #[test]
    fn test_network_to_fork_version_bytes() {
        let fv = network_to_fork_version_bytes(SEPOLIA.name).unwrap();
        assert_eq!(
            fv,
            hex::decode(
                SEPOLIA
                    .genesis_fork_version_hex
                    .strip_prefix("0x")
                    .unwrap_or(SEPOLIA.genesis_fork_version_hex)
            )
            .unwrap()
        );

        let result = network_to_fork_version_bytes(INVALID_NETWORK);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            NetworkError::InvalidName {
                name: INVALID_NETWORK.to_string(),
            }
        );
    }

    #[test]
    fn test_valid_network() {
        let supported_networks = vec![
            "mainnet", "goerli", "sepolia", "holesky", "gnosis", "chiado",
        ];

        let unsupported_networks = vec!["ropsten"];

        for network in supported_networks {
            assert!(valid_network(network), "Network {network} should be valid");
        }

        for network in unsupported_networks {
            assert!(
                !valid_network(network),
                "Network {network} should be invalid"
            );
        }
    }
}
