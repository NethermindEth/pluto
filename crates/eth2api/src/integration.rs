use crate::{
    ConsensusVersion, EthBeaconNodeApiClient, ForkSchedule, GetBlockHeaderRequest,
    GetBlockHeaderRequestPath, GetBlockHeaderResponse,
};
use std::sync::{Arc, OnceLock, Weak};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::sync::Mutex;

#[tokio::test]
async fn get_block_header_head_has_signature() {
    let bn = BeaconNodeContainer::shared().await;
    let client =
        EthBeaconNodeApiClient::with_base_url(&bn.base_url).expect("Failed to create client");

    let response = client
        .get_block_header(GetBlockHeaderRequest {
            path: GetBlockHeaderRequestPath {
                block_id: "head".into(),
            },
        })
        .await
        .expect("Failed to get block header");

    let GetBlockHeaderResponse::Ok(headers) = response else {
        panic!("Expected Ok response, got: {:?}", response)
    };

    assert!(
        !headers.data.header.signature.is_empty(),
        "Signature should not be empty"
    );
}

#[tokio::test]
async fn fetch_genesis_time() {
    let bn = BeaconNodeContainer::shared().await;
    let client =
        EthBeaconNodeApiClient::with_base_url(&bn.base_url).expect("Failed to create client");

    let genesis_time = client
        .fetch_genesis_time()
        .await
        .expect("Failed to fetch genesis time");

    assert_eq!(genesis_time.timestamp(), 1606824023);
}

#[tokio::test]
async fn fetch_slots_config() {
    let bn = BeaconNodeContainer::shared().await;
    let client =
        EthBeaconNodeApiClient::with_base_url(&bn.base_url).expect("Failed to create client");

    let (slot_duration, slots_per_epoch) = client
        .fetch_slots_config()
        .await
        .expect("Failed to fetch slots config");

    assert_eq!(slot_duration.as_secs(), 12);
    assert_eq!(slots_per_epoch, 32);
}

#[tokio::test]
async fn fetch_fork_config() {
    let bn = BeaconNodeContainer::shared().await;
    let base_url = &bn.base_url;
    let client = EthBeaconNodeApiClient::with_base_url(base_url).expect("Failed to create client");

    let fork_schedule = client
        .fetch_fork_config()
        .await
        .expect("Failed to fetch fork schedule");

    let expected = vec![
        (
            ConsensusVersion::Altair,
            ForkSchedule {
                epoch: 74240,
                version: [1, 0, 0, 0],
            },
        ),
        (
            ConsensusVersion::Bellatrix,
            ForkSchedule {
                epoch: 144896,
                version: [2, 0, 0, 0],
            },
        ),
        (
            ConsensusVersion::Capella,
            ForkSchedule {
                epoch: 194048,
                version: [3, 0, 0, 0],
            },
        ),
        (
            ConsensusVersion::Deneb,
            ForkSchedule {
                epoch: 269568,
                version: [4, 0, 0, 0],
            },
        ),
        (
            ConsensusVersion::Electra,
            ForkSchedule {
                epoch: 364032,
                version: [5, 0, 0, 0],
            },
        ),
        (
            ConsensusVersion::Fulu,
            ForkSchedule {
                epoch: 411392,
                version: [6, 0, 0, 0],
            },
        ),
    ]
    .into_iter()
    .collect();

    assert_eq!(fork_schedule, expected);
}

struct BeaconNodeContainer {
    base_url: String,
    // Store the container to keep it alive for the duration of the tests
    _container: ContainerAsync<GenericImage>,
}

impl BeaconNodeContainer {
    // Create a new Lighthouse container configured to run the HTTP API on port 5052
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
                "--http",
                "--http-address",
                "0.0.0.0",
            ])
            .start()
            .await
            .expect("Failed to start Lighthouse container");

        // Get the mapped port for the HTTP API
        let host_port = container
            .get_host_port_ipv4(5052)
            .await
            .expect("Failed to get mapped port");

        // Get the host of the container
        let host = container.get_host().await.expect("Failed to get host");

        // Build the base URL for the API
        let base_url = format!("http://{}:{}", host, host_port);

        Self {
            base_url,
            _container: container,
        }
    }

    /// Get a shared instance of the BeaconNodeContainer.
    ///
    /// The container gets stopped when there are no more references to it.
    async fn shared() -> Arc<BeaconNodeContainer> {
        static SHARED: OnceLock<Mutex<Weak<BeaconNodeContainer>>> = OnceLock::new();
        let mut guard = SHARED.get_or_init(|| Mutex::new(Weak::new())).lock().await;

        if let Some(container) = guard.upgrade() {
            container
        } else {
            let container = Arc::new(BeaconNodeContainer::new().await);
            *guard = Arc::downgrade(&container);

            container
        }
    }
}
