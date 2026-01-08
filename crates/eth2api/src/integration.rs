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
async fn lighthouse_beacon_headers_head() {
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

    // Build an EthBeaconNodeApiClient
    let base_url = format!("http://{}:{}", host, host_port);
    let client = EthBeaconNodeApiClient::with_base_url(base_url).expect("Failed to create client");

    // Invoke the `get_block_header` API with "head" block ID
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

    // Validate the response
    assert!(
        !headers.data.header.signature.is_empty(),
        "Signature should not be empty"
    );
}
