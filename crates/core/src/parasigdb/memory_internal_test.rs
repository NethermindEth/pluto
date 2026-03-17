//! Internal tests for memory ParSigDB.
//! Mirrors the structure of charon/core/parsigdb/memory_internal_test.go

use std::sync::Arc;

use test_case::test_case;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::get_threshold_matching;
use crate::{
    parasigdb::memory::MemDB,
    testutils,
    types::{Duty, DutyType, ParSignedData, Signature, SignedData, SlotNumber},
};

/// Test wrapper for SyncCommitteeMessage (mimics altair.SyncCommitteeMessage).
/// The message root is the BeaconBlockRoot field.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TestSyncCommitteeMessage {
    slot: SlotNumber,
    beacon_block_root: [u8; 32],
    validator_index: u64,
    signature: Signature,
}

impl SignedData for TestSyncCommitteeMessage {
    fn signature(&self) -> Signature {
        self.signature.clone()
    }

    fn set_signature(
        &mut self,
        signature: Signature,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        self.signature = signature;
        Ok(())
    }

    fn message_root(&self) -> [u8; 32] {
        // For SyncCommitteeMessage, the message root is the BeaconBlockRoot
        self.beacon_block_root
    }

    fn clone_box(&self) -> Box<dyn SignedData> {
        Box::new(self.clone())
    }

    fn equals(&self, other: &dyn SignedData) -> bool {
        self.message_root() == other.message_root() && self.signature() == other.signature()
    }
}

/// Test wrapper for BeaconCommitteeSelection (mimics
/// eth2v1.BeaconCommitteeSelection). The message root is computed from the Slot
/// field.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TestBeaconCommitteeSelection {
    validator_index: u64,
    slot: SlotNumber,
    selection_proof: Signature,
}

impl SignedData for TestBeaconCommitteeSelection {
    fn signature(&self) -> Signature {
        self.selection_proof.clone()
    }

    fn set_signature(
        &mut self,
        signature: Signature,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        self.selection_proof = signature;
        Ok(())
    }

    fn message_root(&self) -> [u8; 32] {
        // For BeaconCommitteeSelection, the message root is derived from the slot.
        // We'll use a simple hash: slot number in the first 8 bytes.
        let mut root = [0u8; 32];
        root[0..8].copy_from_slice(&self.slot.inner().to_le_bytes());
        root
    }

    fn clone_box(&self) -> Box<dyn SignedData> {
        Box::new(self.clone())
    }

    fn equals(&self, other: &dyn SignedData) -> bool {
        self.message_root() == other.message_root() && self.signature() == other.signature()
    }
}

/// Helper to create random roots for testing
fn random_root(seed: u8) -> [u8; 32] {
    let mut root = [0u8; 32];
    root[0] = seed;
    root
}

/// Helper to create random signature for testing
fn random_signature(seed: u8) -> Signature {
    let mut sig = [0u8; 96];
    sig[0] = seed;
    Signature::new(sig)
}

/// Copying function here, not using the pluto_cluster::helpers::threshold (not
/// implemented yet) because it would be huge unnecessary dependency for core.
#[allow(clippy::arithmetic_side_effects)]
fn threshold(n: u64) -> u64 {
    (2 * n + 2) / 3
}

// Test cases for get_threshold_matching
// Matches Go test structure from
// memory_internal_test.go:TestGetThresholdMatching
#[test_case(vec![], None ; "empty")]
#[test_case(vec![0, 0, 0], Some(vec![0, 1, 2]) ; "all identical exact threshold")]
#[test_case(vec![0, 0, 0, 0], None ; "all identical above threshold")]
#[test_case(vec![0, 0, 1, 0], Some(vec![0, 1, 3]) ; "one odd")]
#[test_case(vec![0, 0, 1, 1], None ; "two odd")]
#[tokio::test]
async fn test_get_threshold_matching(input: Vec<usize>, output: Option<Vec<usize>>) {
    const N: u64 = 4;

    let slot = SlotNumber::new(123456);
    let val_idx = 42u64;

    // Two different roots to vary message roots
    let roots = [random_root(1), random_root(2)];

    // Test different message types using providers (matches Go approach)
    let providers: Vec<(&str, Box<dyn Fn(usize) -> Box<dyn SignedData>>)> = vec![
        (
            "SyncCommitteeMessage",
            Box::new(|i: usize| {
                Box::new(TestSyncCommitteeMessage {
                    slot,
                    beacon_block_root: roots[input[i]], // Vary root based on input
                    validator_index: val_idx,
                    signature: random_signature(i as u8),
                })
            }),
        ),
        (
            "Selection",
            Box::new(|i: usize| {
                Box::new(TestBeaconCommitteeSelection {
                    validator_index: val_idx,
                    slot: SlotNumber::new(input[i] as u64), // Vary slot based on input
                    selection_proof: random_signature(i as u8),
                })
            }),
        ),
    ];

    for (_, provider) in providers {
        let mut par_sigs: Vec<ParSignedData> = Vec::new();
        for i in 0..input.len() {
            let signed_data = provider(i);
            let par_signed = ParSignedData::new(signed_data, i as u64);
            par_sigs.push(par_signed);
        }

        let th = threshold(N);

        let result = get_threshold_matching(&DutyType::Attester, &par_sigs, th)
            .await
            .expect("get_threshold_matching should not error");

        // Check that if we got a result, it has the correct length (matches Go's ok
        // check)
        if let Some(ref vec) = result {
            assert_eq!(
                vec.len(),
                th as usize,
                "result length should match threshold"
            );
        }

        let out = result.unwrap_or_default();

        let mut expect = Vec::new();
        if let Some(output) = &output {
            for &idx in output {
                expect.push(par_sigs[idx].clone());
            }
        }

        assert_eq!(out, expect, "result should match expected");
    }
}

use pluto_testutil::random as tu_random;

#[tokio::test]
async fn test_mem_db_threshold() {
    const THRESHOLD: u64 = 7;

    let deadliner = TestDeadliner::new();
    let ct = CancellationToken::new();

    let db = Arc::new(MemDB::new(ct.child_token(), THRESHOLD, deadliner.clone()));

    let db_clone = db.clone();
    tokio::spawn(async move {
        db_clone.trim().await;
    });

    let times_called = Arc::new(Mutex::new(0));

    // Using the helper function
    // Note: We need to clone inside because the outer closure is Fn (not FnOnce),
    // so it can be called multiple times
    db.subscribe_threshold(super::threshold_subscriber({
        let times_called = times_called.clone();
        move |_duty, _data| {
            let times_called = times_called.clone();
            async move {
                *times_called.lock().await += 1;
                Ok(())
            }
        }
    }))
    .await
    .unwrap();

    let _pubkey = testutils::random_core_pub_key();
    let _att = tu_random::random_deneb_versioned_attestation();
}

/// Test using the helper function for internal subscriber.
#[tokio::test]
async fn test_mem_db_with_internal_helper() {
    const THRESHOLD: u64 = 7;

    let deadliner = TestDeadliner::new();
    let ct = CancellationToken::new();

    let db = Arc::new(MemDB::new(ct.child_token(), THRESHOLD, deadliner.clone()));

    let db_clone = db.clone();
    tokio::spawn(async move {
        db_clone.trim().await;
    });

    let counter = Arc::new(Mutex::new(0u64));

    // Using the helper function
    // Note: We need to clone inside because the outer closure is Fn (not FnOnce)
    db.subscribe_internal(super::internal_subscriber({
        let counter = counter.clone();
        move |_duty, _set| {
            let counter = counter.clone();
            async move {
                *counter.lock().await += 1;
                Ok(())
            }
        }
    }))
    .await
    .unwrap();

    assert_eq!(*counter.lock().await, 0);
}

/// Test deadliner for unit tests.
pub struct TestDeadliner {
    added: Arc<tokio::sync::Mutex<Vec<Duty>>>,
    ch_tx: tokio::sync::mpsc::Sender<Duty>,
    ch_rx: Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Duty>>>>,
}

impl TestDeadliner {
    /// Creates a new test deadliner.
    #[allow(dead_code)]
    pub fn new() -> Arc<Self> {
        const CHANNEL_BUFFER: usize = 100;
        let (tx, rx) = tokio::sync::mpsc::channel(CHANNEL_BUFFER);
        Arc::new(Self {
            added: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            ch_tx: tx,
            ch_rx: Arc::new(tokio::sync::Mutex::new(Some(rx))),
        })
    }

    /// Expires all added duties.
    #[allow(dead_code)]
    pub async fn expire(&self) -> bool {
        let mut added = self.added.lock().await;
        for duty in added.drain(..) {
            if self.ch_tx.send(duty).await.is_err() {
                return false;
            }
        }
        // Send dummy duty to ensure all piped duties above were processed
        self.ch_tx
            .send(Duty::new(SlotNumber::new(0), DutyType::Unknown))
            .await
            .is_ok()
    }
}

impl crate::deadline::Deadliner for TestDeadliner {
    fn add(&self, duty: Duty) -> futures::future::BoxFuture<'_, bool> {
        Box::pin(async move {
            let mut added = self.added.lock().await;
            added.push(duty);
            true
        })
    }

    fn c(&self) -> Option<tokio::sync::mpsc::Receiver<Duty>> {
        let mut guard = self.ch_rx.blocking_lock();
        guard.take()
    }
}
