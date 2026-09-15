//! Genesis, spec, fork schedule and signing domains.

use crate::{BeaconNodeContainer, GENESIS_FORK_VERSION, GENESIS_TIME, GENESIS_VALIDATORS_ROOT};
use pluto_eth2api::{
    ForkSchedule, Spec,
    spec::{DataVersion, phase0},
    v1,
};

#[tokio::test]
async fn get_genesis_returns_the_mainnet_genesis() {
    let node = BeaconNodeContainer::shared().await;

    let genesis = node.client().get_genesis().await.expect("get genesis");

    assert_eq!(
        genesis,
        v1::Genesis {
            genesis_time: GENESIS_TIME,
            genesis_validators_root: crate::hex_bytes(GENESIS_VALIDATORS_ROOT),
            genesis_fork_version: GENESIS_FORK_VERSION,
        }
    );
}

#[tokio::test]
async fn get_spec_returns_the_mainnet_config() {
    let node = BeaconNodeContainer::shared().await;

    let spec = node.client().get_spec().await.expect("get spec");

    assert_eq!(
        spec,
        Spec {
            seconds_per_slot: 12,
            slots_per_epoch: 32,
            altair_fork_version: [0x01, 0x00, 0x00, 0x00],
            altair_fork_epoch: 74240,
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
            bellatrix_fork_epoch: 144896,
            capella_fork_version: [0x03, 0x00, 0x00, 0x00],
            capella_fork_epoch: 194048,
            deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
            deneb_fork_epoch: 269568,
            electra_fork_version: [0x05, 0x00, 0x00, 0x00],
            electra_fork_epoch: 364032,
            fulu_fork_version: [0x06, 0x00, 0x00, 0x00],
            fulu_fork_epoch: 411392,
            target_aggregators_per_committee: 16,
            sync_committee_size: 512,
            sync_committee_subnet_count: 4,
            target_aggregators_per_sync_subcommittee: 16,
            domain_beacon_proposer: [0x00, 0x00, 0x00, 0x00],
            domain_beacon_attester: [0x01, 0x00, 0x00, 0x00],
            domain_randao: [0x02, 0x00, 0x00, 0x00],
            domain_deposit: [0x03, 0x00, 0x00, 0x00],
            domain_voluntary_exit: [0x04, 0x00, 0x00, 0x00],
            domain_selection_proof: [0x05, 0x00, 0x00, 0x00],
            domain_aggregate_and_proof: [0x06, 0x00, 0x00, 0x00],
            domain_sync_committee: [0x07, 0x00, 0x00, 0x00],
            domain_sync_committee_selection_proof: [0x08, 0x00, 0x00, 0x00],
            domain_contribution_and_proof: [0x09, 0x00, 0x00, 0x00],
            // Lighthouse does not publish DOMAIN_APPLICATION_BUILDER; the client fills in the
            // builder-specs constant.
            domain_application_builder: [0x00, 0x00, 0x00, 0x01],
        }
    );
}

#[tokio::test]
async fn get_fork_schedule_lists_every_mainnet_fork_in_order() {
    let node = BeaconNodeContainer::shared().await;

    let schedule = node
        .client()
        .get_fork_schedule()
        .await
        .expect("get fork schedule");

    let fork = |previous_version, current_version, epoch| phase0::Fork {
        previous_version,
        current_version,
        epoch,
    };
    assert_eq!(
        schedule,
        vec![
            fork([0x00, 0x00, 0x00, 0x00], [0x00, 0x00, 0x00, 0x00], 0),
            fork([0x00, 0x00, 0x00, 0x00], [0x01, 0x00, 0x00, 0x00], 74240),
            fork([0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], 144896),
            fork([0x02, 0x00, 0x00, 0x00], [0x03, 0x00, 0x00, 0x00], 194048),
            fork([0x03, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00], 269568),
            fork([0x04, 0x00, 0x00, 0x00], [0x05, 0x00, 0x00, 0x00], 364032),
            fork([0x05, 0x00, 0x00, 0x00], [0x06, 0x00, 0x00, 0x00], 411392),
        ]
    );
}

#[tokio::test]
async fn fetch_fork_schedule_versions_lists_the_current_versions_in_order() {
    let node = BeaconNodeContainer::shared().await;

    let versions = node
        .client()
        .fetch_fork_schedule_versions()
        .await
        .expect("fetch fork schedule versions");

    assert_eq!(
        versions,
        vec![
            [0x00, 0x00, 0x00, 0x00],
            [0x01, 0x00, 0x00, 0x00],
            [0x02, 0x00, 0x00, 0x00],
            [0x03, 0x00, 0x00, 0x00],
            [0x04, 0x00, 0x00, 0x00],
            [0x05, 0x00, 0x00, 0x00],
            [0x06, 0x00, 0x00, 0x00],
        ]
    );
}

#[tokio::test]
async fn fetch_genesis_domain_uses_the_genesis_fork_and_a_zero_validators_root() {
    let node = BeaconNodeContainer::shared().await;

    let domain = node
        .client()
        .fetch_genesis_domain([0x03, 0x00, 0x00, 0x00])
        .await
        .expect("fetch genesis domain");

    assert_eq!(
        domain,
        crate::hex_bytes("0x03000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9")
    );
}

#[tokio::test]
async fn fetch_domain_at_epoch_zero_uses_the_phase0_fork() {
    let node = BeaconNodeContainer::shared().await;

    let domain = node
        .client()
        .fetch_domain([0x00, 0x00, 0x00, 0x00], 0)
        .await
        .expect("fetch domain");

    assert_eq!(
        domain,
        crate::hex_bytes("0x00000000b5303f2ad2010d699a76c8e62350947421a3e4a979779642cfdb0f66")
    );
}

#[tokio::test]
async fn fetch_beacon_attester_domain_follows_the_fork_schedule() {
    let node = BeaconNodeContainer::shared().await;
    let client = node.client();

    let at_genesis = client
        .fetch_beacon_attester_domain(0)
        .await
        .expect("fetch attester domain at genesis");
    let at_fulu = client
        .fetch_beacon_attester_domain(411392)
        .await
        .expect("fetch attester domain at fulu");

    assert_eq!(
        at_genesis,
        crate::hex_bytes("0x01000000b5303f2ad2010d699a76c8e62350947421a3e4a979779642cfdb0f66")
    );
    assert_eq!(
        at_fulu,
        crate::hex_bytes("0x0100000082fae541f8a3db43adb5e7997ac5f562cf682ce6bc41b8ec28ba1a07")
    );
}

#[tokio::test]
async fn fetch_domain_pins_voluntary_exits_to_the_capella_fork() {
    let node = BeaconNodeContainer::shared().await;

    let domain = node
        .client()
        .fetch_domain([0x04, 0x00, 0x00, 0x00], 411392)
        .await
        .expect("fetch voluntary exit domain");

    assert_eq!(
        domain,
        crate::hex_bytes("0x04000000bba4da96354c9f25476cf1bc69bf583a7f9e0af049305b62de676640")
    );
}

#[tokio::test]
async fn fetch_genesis_time_matches_mainnet() {
    let node = BeaconNodeContainer::shared().await;

    let genesis_time = node
        .client()
        .fetch_genesis_time()
        .await
        .expect("Failed to fetch genesis time");

    assert_eq!(
        genesis_time.timestamp(),
        i64::try_from(GENESIS_TIME).expect("genesis time fits in i64")
    );
}

#[tokio::test]
async fn fetch_slots_config_matches_mainnet() {
    let node = BeaconNodeContainer::shared().await;

    let (slot_duration, slots_per_epoch) = node
        .client()
        .fetch_slots_config()
        .await
        .expect("Failed to fetch slots config");

    assert_eq!(slot_duration.as_secs(), 12);
    assert_eq!(slots_per_epoch, 32);
}

#[tokio::test]
async fn fetch_fork_config_lists_every_fork_after_phase0() {
    let node = BeaconNodeContainer::shared().await;

    let fork_schedule = node
        .client()
        .fetch_fork_config()
        .await
        .expect("Failed to fetch fork schedule");

    let expected = vec![
        (
            DataVersion::Altair,
            ForkSchedule {
                epoch: 74240,
                version: [1, 0, 0, 0],
            },
        ),
        (
            DataVersion::Bellatrix,
            ForkSchedule {
                epoch: 144896,
                version: [2, 0, 0, 0],
            },
        ),
        (
            DataVersion::Capella,
            ForkSchedule {
                epoch: 194048,
                version: [3, 0, 0, 0],
            },
        ),
        (
            DataVersion::Deneb,
            ForkSchedule {
                epoch: 269568,
                version: [4, 0, 0, 0],
            },
        ),
        (
            DataVersion::Electra,
            ForkSchedule {
                epoch: 364032,
                version: [5, 0, 0, 0],
            },
        ),
        (
            DataVersion::Fulu,
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
