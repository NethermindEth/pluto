use std::{sync::Arc, time::Duration};

use pluto_eth2api::{spec::altair, v1};
use pluto_testutil as testutil;
use test_case::test_case;
use tokio::{
    sync::{Mutex, mpsc},
    time::sleep,
};
use tokio_util::sync::CancellationToken;

use super::{MemDB, MemDBError, get_threshold_matching, threshold_subscriber};
use crate::{
    deadline::{DeadlinerTask, NeverExpiringCalculator},
    signeddata::{BeaconCommitteeSelection, SignedSyncMessage, VersionedAttestation},
    testutils::random_core_pub_key,
    types::{Duty, DutyType, ParSignedData, ParSignedDataSet, SlotNumber},
};

fn threshold(nodes: usize) -> u64 {
    (2_u64
        .checked_mul(u64::try_from(nodes).expect("nodes overflow"))
        .expect("nodes overflow"))
    .div_ceil(3)
}

#[test_case(Vec::new(), Vec::new() ; "empty")]
#[test_case(vec![0, 0, 0], vec![0, 1, 2] ; "all identical exact threshold")]
#[test_case(vec![0, 0, 0, 0], Vec::new() ; "all identical above threshold")]
#[test_case(vec![0, 0, 1, 0], vec![0, 1, 3] ; "one odd")]
#[test_case(vec![0, 0, 1, 1], Vec::new() ; "two odd")]
#[tokio::test]
async fn test_get_threshold_matching(input: Vec<usize>, output: Vec<usize>) {
    const N: usize = 4;

    let slot = testutil::random_slot();
    let validator_index = testutil::random_v_idx();
    let roots = [testutil::random_root_bytes(), testutil::random_root_bytes()];
    let threshold = threshold(N);

    type Providers<'a> = [(&'a str, Box<dyn Fn(usize) -> ParSignedData + 'a>); 2];

    let providers: Providers<'_> = [
        (
            "sync_committee_message",
            Box::new(|i| {
                let message = altair::SyncCommitteeMessage {
                    slot,
                    beacon_block_root: roots[input[i]],
                    validator_index,
                    signature: testutil::random_eth2_signature_bytes(),
                };

                SignedSyncMessage::new_partial(message, u64::try_from(i.wrapping_add(1)).unwrap())
            }),
        ),
        (
            "selection",
            Box::new(|i| {
                let selection = v1::BeaconCommitteeSelection {
                    validator_index,
                    slot: u64::try_from(input[i]).unwrap(),
                    selection_proof: testutil::random_eth2_signature_bytes(),
                };

                BeaconCommitteeSelection::new_partial(
                    selection,
                    u64::try_from(i.wrapping_add(1)).unwrap(),
                )
            }),
        ),
    ];

    for (name, provider) in providers {
        let mut data = Vec::new();
        for i in 0..input.len() {
            data.push(provider(i));
        }

        let out = get_threshold_matching(&DutyType::SyncMessage, &data, threshold)
            .expect("threshold matching should succeed");
        let expect: Vec<_> = output.iter().map(|idx| data[*idx].clone()).collect();
        let expected_out = if expect.is_empty() {
            None
        } else {
            Some(expect.clone())
        };

        assert_eq!(expected_out, out, "{name}/output mismatch");
        assert_eq!(
            out.as_ref()
                .map(|matches| u64::try_from(matches.len()).unwrap() == threshold)
                .unwrap_or(false),
            expect.len() as u64 == threshold,
            "{name}/ok mismatch"
        );
    }
}

#[tokio::test]
async fn memdb_threshold() {
    const THRESHOLD: u64 = 7;
    const N: usize = 10;

    let cancel = CancellationToken::new();
    // Real deadliner so `MemDB.store_external` has a handle to call `.add` on.
    // The calculator never expires anything, so the deadliner's natural output
    // is silent — eviction is driven manually through `trim_tx` below.
    let (deadliner, _drop_rx) =
        DeadlinerTask::start(cancel.clone(), "memdb_threshold", NeverExpiringCalculator);
    let (trim_tx, trim_rx) = mpsc::channel::<Duty>(32);
    let db = Arc::new(MemDB::new(cancel.clone(), THRESHOLD, deadliner));

    let trim_handle = tokio::spawn({
        let db = db.clone();
        async move {
            db.trim(trim_rx).await;
        }
    });

    let times_called = Arc::new(Mutex::new(0usize));
    db.subscribe_threshold(threshold_subscriber({
        let times_called = times_called.clone();
        move |_duty, _data| {
            let times_called = times_called.clone();
            async move {
                *times_called.lock().await += 1;
                Ok(())
            }
        }
    }))
    .await;

    let pubkey = random_core_pub_key();
    let attestation = testutil::random_deneb_versioned_attestation();
    let duty = Duty::new_attester_duty(SlotNumber::new(123));

    let enqueue_n = || async {
        for i in 0..N {
            let partial = VersionedAttestation::new_partial(
                attestation.clone(),
                u64::try_from(i + 1).unwrap(),
            )
            .expect("versioned attestation should be valid");

            let mut set = ParSignedDataSet::new();
            set.insert(pubkey, partial);

            db.store_external(&duty, &set)
                .await
                .expect("store_external should succeed");
        }
    };

    enqueue_n().await;
    assert_eq!(1, *times_called.lock().await);

    // Drive eviction manually: simulate the deadliner emitting `duty` as
    // expired. Wait a beat so the trim task processes it.
    trim_tx
        .send(duty.clone())
        .await
        .expect("trim_tx should be open");
    sleep(Duration::from_millis(20)).await;

    enqueue_n().await;
    assert_eq!(2, *times_called.lock().await);

    cancel.cancel();
    trim_handle
        .await
        .expect("trim task should shut down cleanly");
}

/// Builds a `MemDB` (with a real never-expiring deadliner) and a shared
/// threshold-subscriber call counter.
fn memdb_with_counter(threshold: u64) -> (Arc<MemDB>, Arc<Mutex<usize>>, CancellationToken) {
    let cancel = CancellationToken::new();
    let (deadliner, _drop_rx) =
        DeadlinerTask::start(cancel.clone(), "memdb_test", NeverExpiringCalculator);
    let db = Arc::new(MemDB::new(cancel.clone(), threshold, deadliner));
    (db, Arc::new(Mutex::new(0usize)), cancel)
}

#[tokio::test]
async fn store_external_ignores_duplicate() {
    const THRESHOLD: u64 = 3;

    let (db, times_called, cancel) = memdb_with_counter(THRESHOLD);
    db.subscribe_threshold(threshold_subscriber({
        let times_called = times_called.clone();
        move |_duty, _data| {
            let times_called = times_called.clone();
            async move {
                *times_called.lock().await += 1;
                Ok(())
            }
        }
    }))
    .await;

    let pubkey = random_core_pub_key();
    let attestation = testutil::random_deneb_versioned_attestation();
    let duty = Duty::new_attester_duty(SlotNumber::new(123));

    let partial = VersionedAttestation::new_partial(attestation.clone(), 1)
        .expect("versioned attestation should be valid");
    let mut set = ParSignedDataSet::new();
    set.insert(pubkey, partial);

    // Store the identical partial twice: neither reaches the threshold and the
    // duplicate must not error nor fire the subscriber.
    db.store_external(&duty, &set).await.expect("first store");
    db.store_external(&duty, &set)
        .await
        .expect("duplicate store is not an error");

    assert_eq!(0, *times_called.lock().await);
    cancel.cancel();
}

#[tokio::test]
async fn store_external_rejects_share_index_mismatch() {
    const THRESHOLD: u64 = 3;

    let (db, _times_called, cancel) = memdb_with_counter(THRESHOLD);

    let pubkey = random_core_pub_key();
    let duty = Duty::new_attester_duty(SlotNumber::new(123));

    // Two different partials that both claim share index 1 for the same key.
    let first =
        VersionedAttestation::new_partial(testutil::random_deneb_versioned_attestation(), 1)
            .expect("versioned attestation should be valid");
    let second =
        VersionedAttestation::new_partial(testutil::random_deneb_versioned_attestation(), 1)
            .expect("versioned attestation should be valid");

    let mut set1 = ParSignedDataSet::new();
    set1.insert(pubkey, first);
    db.store_external(&duty, &set1).await.expect("first store");

    let mut set2 = ParSignedDataSet::new();
    set2.insert(pubkey, second);
    let err = db
        .store_external(&duty, &set2)
        .await
        .expect_err("conflicting share index must be rejected");
    assert!(matches!(err, MemDBError::ParsigDataMismatch { .. }));

    cancel.cancel();
}
