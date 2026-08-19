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

/// Per-call timeout (seconds) for the ERC-1271 `isValidSignature` request.
///
/// The provider carries a `RetryBackoffLayer` (`MAX_RETRY = 10`) but no request
/// timeout, so a hostile/slow EL endpoint could otherwise stall the call
/// indefinitely. `tokio::time::timeout` wraps the whole retried operation here.
const ERC1271_CALL_TIMEOUT_SECS: u64 = 10;

/// Magic value defined in [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271).
const MAGIC_VALUE: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

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

    /// No execution engine endpoint was configured.
    #[error("execution engine endpoint is not set")]
    NoExecutionEngineAddr,

    /// The ERC-1271 verification call did not complete within the timeout.
    #[error("ERC-1271 call timed out")]
    CallTimeout,
}

/// Defines the interface for the Ethereum EL RPC client.
pub enum EthClient {
    /// Connected client backed by a live provider.
    Connected(DynProvider),
    /// Noop client returned when no address is provided. Mirrors Go's
    /// noopClient.
    Noop,
}

impl EthClient {
    /// Create a new `EthClient`. When `address` is empty a noop client is
    /// returned that errors with [`EthClientError::NoExecutionEngineAddr`]
    /// if `verify_smart_contract_based_signature` is ever called, matching
    /// Go's `NewDefaultEthClientRunner("")` behaviour.
    pub async fn new(address: impl AsRef<str>) -> Result<EthClient> {
        let address = address.as_ref();
        if address.is_empty() {
            return Ok(EthClient::Noop);
        }

        // The maximum number of retries for rate limit errors.
        const MAX_RETRY: u32 = 10;
        // The initial backoff in milliseconds.
        const BACKOFF: u64 = 1000;
        // The number of compute units per second for this provider.
        const CUPS: u64 = 100;

        let retry_layer = RetryBackoffLayer::new(MAX_RETRY, BACKOFF, CUPS);

        let client = ClientBuilder::default()
            .layer(retry_layer)
            .connect(address)
            .await?;

        let provider = ProviderBuilder::new().connect_client(client);

        Ok(EthClient::Connected(provider.erased()))
    }

    /// Check if `sig` is a valid signature of `hash` according to ERC-1271.
    pub async fn verify_smart_contract_based_signature(
        &self,
        contract_address: impl AsRef<str>,
        hash: [u8; 32],
        sig: &[u8],
    ) -> Result<bool> {
        let EthClient::Connected(provider) = self else {
            return Err(EthClientError::NoExecutionEngineAddr);
        };

        // Any casing is accepted (no EIP-55 check), non-hex or wrong-length input
        // is rejected rather than silently zero-padded/truncated.
        let address = contract_address
            .as_ref()
            .parse::<alloy::primitives::Address>()
            .map_err(alloy::primitives::AddressError::from)?;

        let instance = IERC1271::new(address, provider);

        let call = tokio::time::timeout(
            std::time::Duration::from_secs(ERC1271_CALL_TIMEOUT_SECS),
            instance
                .isValidSignature(hash.into(), sig.to_vec().into())
                .call(),
        )
        .await
        .map_err(|_| EthClientError::CallTimeout)??;

        Ok(call == MAGIC_VALUE)
    }
}

#[cfg(test)]
mod tests {
    use alloy::{primitives::Bytes, providers::mock::Asserter};

    use super::*;

    const ADDRESS: &str = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";

    /// ABI-encodes a `bytes4` return value as its 32-byte word.
    fn erc1271_return(value: [u8; 4]) -> Bytes {
        let mut word = [0u8; 32];
        word[..4].copy_from_slice(&value);
        Bytes::copy_from_slice(&word)
    }

    fn mocked_client(asserter: &Asserter) -> EthClient {
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        EthClient::Connected(provider.erased())
    }

    async fn verify(client: &EthClient, contract_address: &str) -> Result<bool> {
        client
            .verify_smart_contract_based_signature(contract_address, [7u8; 32], &[1, 2, 3])
            .await
    }

    #[tokio::test]
    async fn empty_address_returns_noop_client() {
        let client = EthClient::new("").await.expect("noop eth client");
        let err = client
            .verify_smart_contract_based_signature(
                "0x0000000000000000000000000000000000000000",
                [0u8; 32],
                &[],
            )
            .await
            .expect_err("empty address should not verify contract signatures");

        assert!(matches!(err, EthClientError::NoExecutionEngineAddr));
    }

    #[tokio::test]
    async fn any_casing_address_reaches_erc1271_call() {
        // Lowercase, checksummed and wrong-checksum forms of the same address.
        for address in [
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        ] {
            let asserter = Asserter::new();
            asserter.push_success(&erc1271_return(MAGIC_VALUE));

            let valid = verify(&mocked_client(&asserter), address)
                .await
                .expect("address must parse regardless of casing");

            assert!(valid);
        }
    }

    #[tokio::test]
    async fn malformed_address_errors() {
        let client = mocked_client(&Asserter::new());

        for address in ["not-an-address", "0x123"] {
            let err = verify(&client, address)
                .await
                .expect_err("malformed address must not verify");

            assert!(matches!(err, EthClientError::InvalidAddress(_)));
        }
    }

    #[tokio::test]
    async fn non_magic_return_is_invalid() {
        for value in [[0u8; 4], [0xff; 4]] {
            let asserter = Asserter::new();
            asserter.push_success(&erc1271_return(value));

            let valid = verify(&mocked_client(&asserter), ADDRESS)
                .await
                .expect("call must succeed");

            assert!(!valid);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn hanging_erc1271_call_times_out() {
        // A server that accepts but never responds; paused time auto-advances
        // to the call deadline, so the test never actually waits it out.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("local addr"));

        tokio::spawn(async move {
            let mut sockets = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                // Hold sockets open; dropping them fails the request fast
                // with a transport error instead of hanging.
                sockets.push(socket);
            }
        });

        let client = EthClient::new(&endpoint).await.expect("eth client");
        let err = verify(&client, ADDRESS)
            .await
            .expect_err("hanging endpoint must time out");

        assert!(matches!(err, EthClientError::CallTimeout));
    }

    #[tokio::test]
    async fn non_empty_endpoint_returns_connected_client() {
        // HTTP transports connect lazily, so nothing needs to listen here.
        let client = EthClient::new("http://127.0.0.1:1")
            .await
            .expect("eth client");

        assert!(matches!(client, EthClient::Connected(_)));
    }
}
