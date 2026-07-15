//! Single-node in-process simnet boot/readiness test.
//!
//! Drives the real `App::run` with the beacon+validator mocks against an
//! on-disk fixture from [`pluto_cluster::test_cluster::new_for_test`],
//! asserting the node loads the cluster, starts the mocks, binds the validator
//! API, and shuts down cleanly on cancellation.
//!
//! Readiness only, not duty completion: this node is operator 0 of a 2-of-3
//! cluster (cannot reach QBFT quorum alone) and is cancelled as soon as the
//! validator API binds, before the mock drives its first duty. The cross-node
//! duty-submission path is covered by
//! `multinode_parsig_exchange_reaches_submission` in `tests/wiring.rs`.

use std::{net::SocketAddr, time::Duration};

use pluto_app::node::{App, AppConfig};
use tokio_util::sync::CancellationToken;

/// Reserves an ephemeral loopback port. Small TOCTOU race acceptable in a
/// single-process test.
fn available_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read local addr")
}

#[tokio::test]
async fn simnet_single_node_boots_and_serves_validator_api() {
    // Deterministic single-DV, 2-of-3 cluster; GOERLI fork version, whose
    // genesis the beacon mock derives via `fork_version_to_genesis_time`.
    let (lock, p2p_keys, dv_shares) = pluto_cluster::test_cluster::new_for_test(1, 2, 3, 42);

    let dir = tempfile::tempdir().expect("tempdir");

    // cluster-lock.json (Lock's own Serialize matches the loader's format).
    let lock_file = dir.path().join("cluster-lock.json");
    std::fs::write(
        &lock_file,
        serde_json::to_vec(&lock).expect("serialize lock"),
    )
    .expect("write lock");

    // This node is operator 0; write its secp256k1 ENR key.
    let priv_key_file = dir.path().join("charon-enr-private-key");
    pluto_k1util::save(&p2p_keys[0], &priv_key_file).expect("save enr key");

    // Node 0's per-DV BLS share secrets, written as EIP-2335 keystores for the
    // validator mock to load.
    let keys_dir = dir.path().join("validator_keys");
    std::fs::create_dir_all(&keys_dir).expect("create keys dir");
    let node0_secrets: Vec<_> = dv_shares.iter().map(|per_dv| per_dv[0]).collect();
    pluto_eth2util::keystore::store_keys_insecure(
        &node0_secrets,
        &keys_dir,
        &pluto_eth2util::keystore::CONFIRM_INSECURE_KEYS,
    )
    .await
    .expect("store keystores");

    let validator_api_addr = available_addr();
    let config = AppConfig {
        p2p: pluto_p2p::config::P2PConfig {
            tcp_addrs: vec![format!("127.0.0.1:{}", available_addr().port())],
            ..Default::default()
        },
        lock_file,
        priv_key_file,
        priv_key_locking: false,
        beacon_node_addrs: Vec::new(),
        beacon_node_timeout: Duration::from_secs(10),
        beacon_node_submit_timeout: Duration::from_secs(10),
        validator_api_addr,
        monitoring_addr: available_addr(),
        builder_api: false,
        nickname: "simnet-test".to_string(),
        no_verify: true,
        eth1_endpoint: None,
        graffiti: None,
        graffiti_disable_client_append: false,
        feature: pluto_featureset::Config::default(),
        simnet_beacon_mock: true,
        simnet_validator_mock: true,
        simnet_beacon_mock_fuzz: false,
        simnet_slot_duration: Duration::from_secs(1),
        simnet_validator_keys_dir: keys_dir,
    };

    let ct = CancellationToken::new();
    let node = tokio::spawn(App::new(config).run(ct.clone()));

    // The validator API must accept TCP connections once the node is up.
    let ready = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if tokio::net::TcpStream::connect(validator_api_addr)
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        ready.is_ok(),
        "validator API {validator_api_addr} did not bind within 30s"
    );

    // Cancellation must drive an ordered, clean shutdown.
    ct.cancel();
    let result = tokio::time::timeout(Duration::from_secs(15), node)
        .await
        .expect("run did not exit within 15s of cancellation")
        .expect("run task panicked");
    assert!(result.is_ok(), "run returned an error: {result:?}");
}
