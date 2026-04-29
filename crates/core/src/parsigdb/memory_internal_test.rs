use std::{
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use pluto_eth2api::{spec::altair, v1};
use pluto_testutil as testutil;
use test_case::test_case;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use super::{MemDB, get_threshold_matching, threshold_subscriber};
use crate::{
    deadline::Deadliner,
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
            .await
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

    let deadliner = Arc::new(TestDeadliner::new());
    let cancel = CancellationToken::new();
    let db = Arc::new(MemDB::new(cancel.clone(), THRESHOLD, deadliner.clone()));

    let trim_handle = tokio::spawn({
        let db = db.clone();
        async move {
            db.trim().await;
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

    deadliner.expire().await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    enqueue_n().await;
    assert_eq!(2, *times_called.lock().await);

    cancel.cancel();
    trim_handle
        .await
        .expect("trim task should shut down cleanly");
}

struct TestDeadliner {
    added: StdMutex<Vec<Duty>>,
    tx: mpsc::Sender<Duty>,
    rx: StdMutex<Option<mpsc::Receiver<Duty>>>,
}

impl TestDeadliner {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel(32);
        Self {
            added: StdMutex::new(Vec::new()),
            tx,
            rx: StdMutex::new(Some(rx)),
        }
    }

    async fn expire(&self) -> bool {
        let duties = {
            let mut added = self.added.lock().expect("test deadliner lock poisoned");
            std::mem::take(&mut *added)
        };

        for duty in duties {
            if self.tx.send(duty).await.is_err() {
                return false;
            }
        }

        true
    }
}

#[async_trait::async_trait]
impl Deadliner for TestDeadliner {
    async fn add(&self, duty: Duty) -> bool {
        self.added
            .lock()
            .expect("test deadliner lock poisoned")
            .push(duty);
        true
    }

    fn c(&self) -> Option<mpsc::Receiver<Duty>> {
        self.rx.lock().expect("test deadliner lock poisoned").take()
    }
}
