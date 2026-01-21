use serde::{Deserialize, Serialize};

/// Gwei represents an amount in Gwei (1 ETH = 1,000,000,000 Gwei)
/// This matches eth2p0.Gwei from the Go implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Gwei(pub u64);

impl Gwei {
    /// Create a new Gwei amount
    pub const fn new(amount: u64) -> Self {
        Self(amount)
    }

    /// Get the inner u64 value
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<u64> for Gwei {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Gwei> for u64 {
    fn from(value: Gwei) -> Self {
        value.0
    }
}

impl std::fmt::Display for Gwei {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Add for Gwei {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl std::ops::Mul<u64> for Gwei {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_mul(rhs))
    }
}

impl std::ops::Mul<Gwei> for u64 {
    type Output = Gwei;

    fn mul(self, rhs: Gwei) -> Self::Output {
        Gwei(self.saturating_mul(rhs.0))
    }
}

impl std::ops::Sub for Gwei {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl std::ops::Div<u64> for Gwei {
    type Output = Self;

    fn div(self, rhs: u64) -> Self::Output {
        Self(self.0 / rhs)
    }
}

// TreeHash implementation for Gwei (delegates to u64)
impl tree_hash::TreeHash for Gwei {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        u64::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        u64::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

/// One ETH in Gwei (1 ETH = 1,000,000,000 Gwei)
pub const ONE_ETH_IN_GWEI: Gwei = Gwei(1_000_000_000);

/// Minimum allowed deposit amount (1 ETH)
pub const MIN_DEPOSIT_AMOUNT: Gwei = Gwei(1_000_000_000);

/// Default deposit amount (32 ETH)
pub const DEFAULT_DEPOSIT_AMOUNT: Gwei = Gwei(32_000_000_000);

/// Maximum allowed deposit amount when compounding is enabled (2048 ETH)
pub const MAX_COMPOUNDING_DEPOSIT_AMOUNT: Gwei = Gwei(2_048_000_000_000);

/// Maximum allowed deposit amount when compounding is disabled (32 ETH)
pub const MAX_STANDARD_DEPOSIT_AMOUNT: Gwei = Gwei(32_000_000_000);

/// Deposit CLI version for compatibility
pub const DEPOSIT_CLI_VERSION: &str = "2.7.0";

/// ETH1 address withdrawal prefix (0x01)
pub const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;

/// EIP-7251 address withdrawal prefix for compounding (0x02)
pub const EIP7251_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x02;

/// DOMAIN_DEPOSIT type as per ETH2 spec
/// See: https://benjaminion.xyz/eth2-annotated-spec/phase0/beacon-chain/#domain-types
pub const DEPOSIT_DOMAIN_TYPE: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

/// Fork version type (4 bytes).
/// Corresponds to eth2p0.Version in Go implementation.
pub type Version = [u8; 4];

/// Domain type (32 bytes).
/// Corresponds to eth2p0.Domain in Go implementation.
pub type Domain = [u8; 32];

/// Root type (32 bytes).
/// Corresponds to eth2p0.Root in Go implementation.
pub type Root = [u8; 32];
