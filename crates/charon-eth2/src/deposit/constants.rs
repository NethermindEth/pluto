use super::types::Gwei;

/// One ETH in Gwei (1 ETH = 1,000,000,000 Gwei)
pub const ONE_ETH_IN_GWEI: Gwei = 1_000_000_000;

/// Minimum allowed deposit amount (1 ETH)
pub const MIN_DEPOSIT_AMOUNT: Gwei = 1_000_000_000;

/// Default deposit amount (32 ETH)
pub const DEFAULT_DEPOSIT_AMOUNT: Gwei = 32_000_000_000;

/// Maximum allowed deposit amount when compounding is enabled (2048 ETH)
pub const MAX_COMPOUNDING_DEPOSIT_AMOUNT: Gwei = 2_048_000_000_000;

/// Maximum allowed deposit amount when compounding is disabled (32 ETH)
pub const MAX_STANDARD_DEPOSIT_AMOUNT: Gwei = 32_000_000_000;

/// Deposit CLI version for compatibility
pub const DEPOSIT_CLI_VERSION: &str = "2.7.0";

/// ETH1 address withdrawal prefix (0x01)
pub const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;

/// EIP-7251 address withdrawal prefix for compounding (0x02)
pub const EIP7251_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x02;

/// DOMAIN_DEPOSIT type as per ETH2 spec
/// See: https://benjaminion.xyz/eth2-annotated-spec/phase0/beacon-chain/#domain-types
pub const DEPOSIT_DOMAIN_TYPE: [u8; 4] = [0x03, 0x00, 0x00, 0x00];
