//! Ethereum EL RPC client wrapper.

use alloy::{
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::client::ClientBuilder,
    sol,
    transports::{self, layers::RetryBackoffLayer},
};

sol!(
    #[sol(rpc)]
    IERC1271,
    "src/build/IERC1271.abi"
);

type Result<T> = std::result::Result<T, EthClientError>;

/// Defines errors that can occur when interacting with the Ethereum client.
#[derive(Debug, thiserror::Error)]
pub enum EthClientError {
    /// An RPC error.
    #[error("RPC error: {0}")]
    RpcTransportError(#[from] alloy::transports::RpcError<transports::TransportErrorKind>),

    /// Error when interacting with contracts.
    #[error("Contract error: {0}")]
    ContractError(#[from] alloy::contract::Error),

    /// The URL provided was invalid.
    #[error("URL parse error: {0}")]
    UrlParseError(#[from] url::ParseError),

    /// The Ethereum Address was invalid.
    #[error("Invalid address: {0}")]
    InvalidAddress(#[from] alloy::primitives::AddressError),
}

/// Defines the interface for the Ethereum EL RPC client.
pub struct EthClient(DynProvider);

impl std::ops::Deref for EthClient {
    type Target = DynProvider;

    fn deref(&self) -> &DynProvider {
        &self.0
    }
}

impl EthClient {
    /// Create a new `EthClient` connected to the given address using defaults
    /// for retry.
    pub async fn new(address: impl AsRef<str>) -> Result<EthClient> {
        // The maximum number of retries for rate limit errors.
        const MAX_RETRY: u32 = 10;
        // The initial backoff in milliseconds.
        const BACKOFF: u64 = 1000;
        // The number of compute units per second for this provider.
        const CUPS: u64 = 100;

        let retry_layer = RetryBackoffLayer::new(MAX_RETRY, BACKOFF, CUPS);

        let client = ClientBuilder::default()
            .layer(retry_layer)
            .connect(address.as_ref())
            .await?;

        let provider = ProviderBuilder::new().connect_client(client);

        Ok(EthClient(provider.erased()))
    }

    /// Check if `sig` is a valid signature of `hash` according to ERC-1271.
    pub async fn verify_smart_contract_based_signature(
        &self,
        contract_address: impl AsRef<str>,
        hash: [u8; 32],
        sig: &[u8],
    ) -> Result<bool> {
        // Magic value defined in [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271).
        const MAGIC_VALUE: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

        let address = alloy::primitives::Address::parse_checksummed(contract_address, None)?;

        let instance = IERC1271::new(address, &self.0);

        let call = instance
            .isValidSignature(hash.into(), sig.to_vec().into())
            .call()
            .await?;

        Ok(call == MAGIC_VALUE)
    }
}
