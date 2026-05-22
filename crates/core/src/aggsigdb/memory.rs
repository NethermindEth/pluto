use crate::{deadline::Deadliner, types};
use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};
use tokio::sync::{Mutex, Notify};

/// Errors for the in-memory AggSigDB implementation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Data for the same duty and public key already exists but does not match
    /// the new data.
    #[error("Mismatching data")]
    MismatchingData,
}

/// An in-memory implementation of the AggSigDB.
///
/// Share an instance by cloning. Cloning is cheap and creates a new reference
/// to the same underlying data.
#[derive(Clone)]
pub struct MemDB(Arc<MemDBInner>);

type SignedDataByPubKey = HashMap<types::PubKey, Box<dyn types::SignedData>>;

struct MemDBInner {
    data: Mutex<HashMap<types::Duty, SignedDataByPubKey>>,
    deadliner: Arc<dyn Deadliner>,
    notify: Notify,
}

impl MemDB {
    /// Creates a new in-memory AggSigDB instance.
    pub fn new(deadliner: Arc<dyn Deadliner>) -> Self {
        let this = Self(Arc::new(MemDBInner {
            data: Mutex::new(HashMap::new()),
            deadliner: Arc::clone(&deadliner),
            notify: Notify::new(),
        }));

        match deadliner.c() {
            Some(evictions) => {
                tokio::spawn(Self::evict(Arc::downgrade(&this.0), evictions));
            }
            None => {
                tracing::warn!("Deadliner channel is not available");
            }
        }

        this
    }

    async fn evict(
        inner: std::sync::Weak<MemDBInner>,
        mut evictions: tokio::sync::mpsc::Receiver<types::Duty>,
    ) {
        while let Some(duty) = evictions.recv().await {
            let Some(inner) = inner.upgrade() else {
                return;
            };
            inner.data.lock().await.remove(&duty);
        }
    }

    /// Stores aggregated signed duty data set.
    pub async fn store(&self, duty: types::Duty, set: types::SignedDataSet) -> Result<(), Error> {
        let mut should_notify = false;

        let result = {
            let mut data = self.0.data.lock().await;
            // TODO(charon): Distinguish between no deadline supported vs already expired.
            let _ = self.0.deadliner.add(duty.clone()).await;

            // NOTE: Partial insertions on error match the semantics of Charon.
            let for_duty = data.entry(duty).or_default();

            set.into_iter()
                .try_for_each(|(pub_key, signed_data)| match for_duty.entry(pub_key) {
                    Entry::Vacant(slot) => {
                        slot.insert(signed_data);
                        should_notify = true;
                        Ok(())
                    }
                    Entry::Occupied(slot) if slot.get() != &signed_data => {
                        Err(Error::MismatchingData)
                    }
                    Entry::Occupied(_) => Ok(()),
                })
        };

        if should_notify {
            // TODO: Optimize to only wake those who are waiting for the specific duty and
            // pubkey, rather than all waiters.
            self.0.notify.notify_waiters();
        }

        result
    }

    /// Blocks and returns the aggregated signed duty data when available.
    ///
    /// Might block indefinitely if no data is ever stored for the given duty
    /// and public key.
    pub async fn wait_for(
        &self,
        duty: types::Duty,
        pub_key: types::PubKey,
    ) -> Box<dyn types::SignedData> {
        loop {
            // Register interest before checking the map so that a concurrent `store` either
            // (a) inserts before we check and we observe the value, or (b) inserts after
            // our `notified()` is enabled and wakes us.
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            {
                if let Some(data) = self.get(&duty, &pub_key).await {
                    return data.clone();
                }
            }

            notified.await;
        }
    }

    /// Immediately returns the aggregated signed duty data if available,
    /// without blocking.
    pub async fn get(
        &self,
        duty: &types::Duty,
        pub_key: &types::PubKey,
    ) -> Option<Box<dyn types::SignedData>> {
        let data = self.0.data.lock().await;
        data.get(duty).and_then(|inner| inner.get(pub_key)).cloned()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deadline::Deadliner,
        signeddata::SignedDataError,
        types::{Duty, PubKey, Signature, SignedData, SignedDataSet, SlotNumber},
    };
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::sync;

    /// Some mock signed data type for testing.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockSignedData(u8);

    impl SignedData for MockSignedData {
        fn signature(&self) -> Result<Signature, SignedDataError> {
            Ok(Signature::new([self.0; 96]))
        }

        fn set_signature(&self, _signature: Signature) -> Result<Self, SignedDataError> {
            Ok(self.clone())
        }

        fn message_root(&self) -> Result<[u8; 32], SignedDataError> {
            Ok([self.0; 32])
        }
    }

    impl MockSignedData {
        fn singleton(&self, pub_key: PubKey) -> SignedDataSet {
            let mut set = SignedDataSet::new();
            set.insert(pub_key, self.clone());
            set
        }

        fn boxed(&self) -> Box<dyn SignedData> {
            Box::new(self.clone())
        }
    }

    /// Deadliner that hands out a caller-supplied receiver, allowing tests to
    /// drive eviction by sending on the paired sender.
    struct TestDeadliner(std::sync::Mutex<Option<sync::mpsc::Receiver<Duty>>>);

    impl TestDeadliner {
        fn new(receiver: sync::mpsc::Receiver<Duty>) -> Arc<Self> {
            Arc::new(Self(std::sync::Mutex::new(Some(receiver))))
        }

        /// Creates a deadliner that never returns any duties to evict, so no
        /// eviction will occur.
        fn never() -> Arc<Self> {
            Arc::new(Self(std::sync::Mutex::new(None)))
        }
    }

    #[async_trait]
    impl Deadliner for TestDeadliner {
        async fn add(&self, _duty: Duty) -> bool {
            true
        }

        fn c(&self) -> Option<sync::mpsc::Receiver<Duty>> {
            self.0.lock().unwrap().take()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_read() {
        let store = super::MemDB::new(TestDeadliner::never());

        let duty = Duty::new_proposer_duty(SlotNumber::new(10));
        let pub_key = PubKey::new([7u8; 48]);
        let signed_data = MockSignedData(42);

        store
            .store(duty.clone(), signed_data.singleton(pub_key))
            .await
            .unwrap();

        let result = store.wait_for(duty, pub_key).await;
        assert_eq!(result, signed_data.boxed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_unblocks() {
        let deadliner = TestDeadliner::never();
        let store = super::MemDB::new(deadliner);

        let duty = Duty::new_attester_duty(SlotNumber::new(1));
        let pub_key = PubKey::new([7u8; 48]);
        let signed_data = MockSignedData(0);

        let reader = {
            let store = store.clone();
            let duty = duty.clone();

            tokio::spawn(async move { store.wait_for(duty, pub_key).await })
        };

        // Give the reader a chance to reach `notified.await` before we store, so the
        // test actually exercises the notify wakeup path rather than the
        // fast-path lookup.
        tokio::task::yield_now().await;
        assert!(!reader.is_finished(), "wait_for should block until store");

        let write = store.store(duty, signed_data.singleton(pub_key)).await;
        let read = reader.await.unwrap();

        assert!(write.is_ok());
        assert_eq!(read, signed_data.boxed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cannot_overwrite() {
        let store = super::MemDB::new(TestDeadliner::never());

        let duty = Duty::new_proposer_duty(SlotNumber::new(10));
        let pub_key = PubKey::new([7u8; 48]);
        let first = MockSignedData(1);
        let second = MockSignedData(2);

        store
            .store(duty.clone(), first.singleton(pub_key))
            .await
            .unwrap();

        let err = store
            .store(duty, second.singleton(pub_key))
            .await
            .expect_err("storing mismatching data should fail");
        assert!(matches!(err, super::Error::MismatchingData));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_idempotent() {
        let store = super::MemDB::new(TestDeadliner::never());

        let duty = Duty::new_proposer_duty(SlotNumber::new(10));
        let pub_key = PubKey::new([7u8; 48]);
        let signed_data = MockSignedData(42);

        store
            .store(duty.clone(), signed_data.singleton(pub_key))
            .await
            .unwrap();
        store
            .store(duty.clone(), signed_data.singleton(pub_key))
            .await
            .unwrap();

        let result = store.wait_for(duty, pub_key).await;
        assert_eq!(result, signed_data.boxed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_evict_wait_then_write() {
        let (evict_tx, evict_rx) = sync::mpsc::channel::<Duty>(1);
        let deadliner = TestDeadliner::new(evict_rx);

        let store = super::MemDB::new(deadliner);

        let duty = Duty::new_attester_duty(SlotNumber::new(1));
        let pub_key = PubKey::new([7u8; 48]);
        let first = MockSignedData(1);
        let second = MockSignedData(2);

        store
            .store(duty.clone(), first.singleton(pub_key))
            .await
            .unwrap();

        // The eviction task runs concurrently, so we poll until the specific
        // data gone, so new readers are guaranteed to not observe it.
        evict_tx.send(duty.clone()).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while store.get(&duty, &pub_key).await.is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("eviction was not applied in time");

        let reader = {
            let store = store.clone();
            let duty = duty.clone();

            tokio::spawn(async move { store.wait_for(duty, pub_key).await })
        };

        // The eviction has been applied, so wait_for has no entry to return and must
        // block.
        tokio::task::yield_now().await;
        assert!(!reader.is_finished(), "wait_for should block until store");

        // Store new data for the same duty and pubkey. The reader should wake up and
        // return the new data, not the evicted data.
        store.store(duty, second.singleton(pub_key)).await.unwrap();

        let read = reader.await.unwrap();
        assert_eq!(read, second.boxed());
        assert_ne!(read, first.boxed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn write_unblocks_many() {
        const N: usize = 4;

        let store = super::MemDB::new(TestDeadliner::never());
        let duty = Duty::new_proposer_duty(SlotNumber::new(10));
        let pub_key = PubKey::new([7u8; 48]);
        let signed_data = MockSignedData(42);

        let readers: Vec<_> = (0..N)
            .map(|_| {
                let store = store.clone();
                let duty = duty.clone();
                tokio::spawn(async move { store.wait_for(duty, pub_key).await })
            })
            .collect();

        // Give readers a chance to reach `notified.await` before the store.
        tokio::task::yield_now().await;
        for reader in &readers {
            assert!(
                !reader.is_finished(),
                "all readers should block until store"
            );
        }

        // A single store unblocks all readers.
        store
            .store(duty, signed_data.singleton(pub_key))
            .await
            .unwrap();

        for reader in readers {
            let read = reader.await.unwrap();
            assert_eq!(read, signed_data.boxed());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unrelated_write_does_not_unblock() {
        let store = super::MemDB::new(TestDeadliner::never());

        let duty_a = Duty::new_proposer_duty(SlotNumber::new(10));
        let data_a = MockSignedData(1);

        let duty_b = Duty::new_attester_duty(SlotNumber::new(20));
        let data_b = MockSignedData(2);

        let pub_key = PubKey::new([7u8; 48]);

        let reader = {
            let store = store.clone();
            let duty_a = duty_a.clone();
            tokio::spawn(async move { store.wait_for(duty_a, pub_key).await })
        };

        tokio::task::yield_now().await;
        assert!(!reader.is_finished(), "reader should block initially");

        // Storing an unrelated key wakes readers, which block again since the store is
        // unrelated.
        store
            .store(duty_b, data_b.singleton(pub_key))
            .await
            .unwrap();

        tokio::task::yield_now().await;
        assert!(
            !reader.is_finished(),
            "reader should re-block after unrelated store"
        );

        // Storing the actual key unblocks the reader.
        store
            .store(duty_a, data_a.singleton(pub_key))
            .await
            .unwrap();

        let read = reader.await.unwrap();
        assert_eq!(read, data_a.boxed());
        assert_ne!(read, data_b.boxed());
    }
}
