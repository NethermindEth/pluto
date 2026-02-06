use crate::{
    EthBeaconNodeApiClient, GetBlockHeaderRequest, GetBlockHeaderRequestPath,
    GetBlockHeaderResponse,
};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

#[tokio::test]
async fn get_block_header_head_has_signature() {
    with_lighthouse(async |base_url| {
        let client =
            EthBeaconNodeApiClient::with_base_url(base_url).expect("Failed to create client");

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
    })
    .await;
}

#[tokio::test]
async fn fetch_genesis_time() {
    with_lighthouse(async |base_url| {
        let client =
            EthBeaconNodeApiClient::with_base_url(base_url).expect("Failed to create client");

        let genesis_time = client
            .fetch_genesis_time()
            .await
            .expect("Failed to fetch genesis time");

        assert_eq!(genesis_time.timestamp(), 1606824023);
    })
    .await;
}

#[tokio::test]
async fn fetch_slots_config() {
    with_lighthouse(async |base_url| {
        let client =
            EthBeaconNodeApiClient::with_base_url(base_url).expect("Failed to create client");

        let (slot_duration, slots_per_epoch) = client
            .fetch_slots_config()
            .await
            .expect("Failed to fetch slots config");

        assert_eq!(slot_duration.as_secs(), 12);
        assert_eq!(slots_per_epoch, 32);
    })
    .await;
}

async fn with_lighthouse<F, Fut>(body: F)
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = ()>,
{
    // Create the Lighthouse container with required configuration
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

    body(base_url).await;
}
