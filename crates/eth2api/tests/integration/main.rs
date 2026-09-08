//! Live tests of [`EthBeaconNodeApiClient`] against a Lighthouse beacon node
//! running in a Docker container.
//!
//! The node runs on mainnet with discovery, UPnP and peering disabled, so it
//! never syncs past the genesis block and every response is a fixed mainnet
//! genesis value that the tests assert as a literal.
//!
//! Requires Docker and the `integration` feature:
//! `cargo test -p pluto-eth2api --features integration`.

mod attestations;
mod blocks;
mod chain;
mod duties;
mod node;
mod proposals;
mod validators;

use pluto_eth2api::{EthBeaconNodeApiClient, spec::phase0};
use std::sync::{Arc, LazyLock, Weak};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::sync::Mutex;

pub(crate) const GENESIS_TIME: u64 = 1606824023;
pub(crate) const GENESIS_FORK_VERSION: phase0::Version = [0x00, 0x00, 0x00, 0x00];
pub(crate) const GENESIS_VALIDATORS_ROOT: &str =
    "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";
pub(crate) const GENESIS_BLOCK_ROOT: &str =
    "0x4d611d5b93fdab69013a7f0a2f961caca0c853f87cfe9595fe50038163079360";
pub(crate) const GENESIS_STATE_ROOT: &str =
    "0x7e76880eb67bbdc86250aa578958e9d0675e64e714337855204fb5abaaf82c2b";
pub(crate) const VALIDATOR_0_PUBKEY: &str = "0x933ad9491b62059dd065b560d256d8957a8c402cc6e8d8ee7290ae11e8f7329267a8811c397529dac52ae1342ba58c95";
pub(crate) const VALIDATOR_1_PUBKEY: &str = "0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c";

/// Decodes a `0x`-prefixed hex literal into an `N`-byte array.
pub(crate) fn hex_bytes<const N: usize>(literal: &str) -> [u8; N] {
    let hex = literal
        .strip_prefix("0x")
        .expect("hex literal starts with 0x");
    let bytes = hex::decode(hex).expect("valid hex literal");
    bytes
        .try_into()
        .expect("hex literal has the expected length")
}

/// A Lighthouse container and the base URL of its HTTP API.
pub(crate) struct BeaconNodeContainer {
    base_url: String,
    // Keeps the container alive for the duration of the tests.
    _container: ContainerAsync<GenericImage>,
}

impl BeaconNodeContainer {
    pub(crate) fn client(&self) -> EthBeaconNodeApiClient {
        EthBeaconNodeApiClient::with_base_url(&self.base_url)
            .expect("client for the shared container")
    }

    async fn new() -> Self {
        let container = GenericImage::new("sigp/lighthouse", "v8.0.1")
            .with_exposed_port(5052.tcp())
            .with_wait_for(WaitFor::message_on_stdout("HTTP API started"))
            .with_cmd(vec![
                "lighthouse",
                "bn",
                "--network",
                "mainnet",
                "--execution-jwt-secret-key",
                // Intentionally insecure all-zeros JWT secret used only for this test container.
                "0000000000000000000000000000000000000000000000000000000000000000",
                "--allow-insecure-genesis-sync",
                "--execution-endpoint",
                "http://localhost:8551",
                "--disable-discovery",
                "--disable-upnp",
                "--target-peers",
                "0",
                "--http",
                "--http-address",
                "0.0.0.0",
            ])
            .start()
            .await
            .expect("Failed to start Lighthouse container");

        let host_port = container
            .get_host_port_ipv4(5052)
            .await
            .expect("Failed to get mapped port");
        let host = container.get_host().await.expect("Failed to get host");

        Self {
            base_url: format!("http://{host}:{host_port}"),
            _container: container,
        }
    }

    /// Get a shared instance of the BeaconNodeContainer.
    ///
    /// The container gets stopped when there are no more references to it.
    pub(crate) async fn shared() -> Arc<BeaconNodeContainer> {
        static SHARED: LazyLock<Mutex<Weak<BeaconNodeContainer>>> =
            LazyLock::new(|| Mutex::new(Weak::new()));
        let mut guard = SHARED.lock().await;

        if let Some(container) = guard.upgrade() {
            container
        } else {
            let container = Arc::new(BeaconNodeContainer::new().await);
            *guard = Arc::downgrade(&container);

            container
        }
    }
}
