use crate::{deadline::Deadliner, types};
use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};
use tokio::sync;

/// Errors for the in-memory AggSigDB implementation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Data for the same duty and public key already exists but does not match
    /// the new data.
    #[error("Mismatching data")]
    MismatchingData,
}

struct Actor {
    entries: HashMap<types::Duty, HashMap<types::PubKey, Box<dyn types::SignedData>>>,
    waiters: HashMap<
        (types::Duty, types::PubKey),
        Vec<sync::oneshot::Sender<Box<dyn types::SignedData>>>,
    >,
    deadliner: Arc<dyn Deadliner>,
}

impl Actor {
    async fn run(&mut self, mut messages: sync::mpsc::Receiver<Message>) {
        while let Some(msg) = messages.recv().await {
            match msg {
                Message::Store {
                    duty,
                    set,
                    response,
                } => {
                    let result = self.store(duty, set).await;
                    let _ = response.send(result);
                }
                Message::WaitFor {
                    duty,
                    pub_key,
                    response,
                } => {
                    if let Some(found) = self.get(&duty, &pub_key) {
                        let _ = response.send(found);
                    } else {
                        self.waiters
                            .entry((duty, pub_key))
                            .or_default()
                            .push(response);
                    }
                }
                Message::Evict { duty } => {
                    let _ = self.evict(duty);
                }
            }
        }
    }

    async fn store(&mut self, duty: types::Duty, set: types::SignedDataSet) -> Result<(), Error> {
        // TODO: Improve the `deadliner` API:
        // - Return if the duty is already expired. If so, return early.
        // - Make `add` sync to avoid an `await` which blocks the actor.
        let _ = self.deadliner.add(duty.clone()).await;

        // NOTE: Partial insertions on error match the semantics of Charon.
        let for_duty = self.entries.entry(duty.clone()).or_default();
        for (pub_key, signed_data) in set.into_iter() {
            match for_duty.entry(pub_key) {
                Entry::Vacant(slot) => {
                    slot.insert(signed_data.clone());

                    let k = (duty.clone(), pub_key);
                    if let Some((_, waiters)) = self.waiters.remove_entry(&k) {
                        for w in waiters {
                            let _ = w.send(signed_data.clone());
                        }
                    };
                }
                Entry::Occupied(slot) if slot.get() != &signed_data => {
                    return Err(Error::MismatchingData);
                }
                Entry::Occupied(_) => {}
            }
        }

        Ok(())
    }

    fn get(
        &self,
        duty: &types::Duty,
        pub_key: &types::PubKey,
    ) -> Option<Box<dyn types::SignedData>> {
        self.entries
            .get(duty)
            .and_then(|for_duty| for_duty.get(pub_key))
            .cloned()
    }

    fn evict(&mut self, duty: types::Duty) {
        self.entries.remove(&duty);
    }
}

enum Message {
    Evict {
        duty: types::Duty,
    },
    Store {
        duty: types::Duty,
        set: types::SignedDataSet,
        response: sync::oneshot::Sender<Result<(), Error>>,
    },
    WaitFor {
        duty: types::Duty,
        pub_key: types::PubKey,
        response: sync::oneshot::Sender<Box<dyn types::SignedData>>,
    },
}

/// An in-memory implementation of AggSigDB.
///
/// Share an instance by cloning. Cloning is cheap and creates a new reference
/// to the same underlying data.
#[derive(Clone)]
pub struct Handle {
    sender: sync::mpsc::Sender<Message>,
}

impl Handle {
    /// Creates a new in-memory AggSigDB instance, and get a handle to it.
    ///
    /// The underlying instance gets dropped when all handles are dropped.
    pub fn new(deadliner: Arc<dyn Deadliner>) -> Self {
        let (sender, receiver) = sync::mpsc::channel(100);
        let mut actor = Actor {
            entries: HashMap::new(),
            waiters: HashMap::new(),
            deadliner: Arc::clone(&deadliner),
        };
        tokio::spawn(async move { actor.run(receiver).await });

        let deadliner_sender = sender.clone();
        tokio::spawn(async move {
            if let Some(mut c) = deadliner.c() {
                while let Some(duty) = c.recv().await {
                    let _ = deadliner_sender.send(Message::Evict { duty }).await;
                }
            }
        });

        Self { sender }
    }

    /// Stores aggregated signed duty data set.
    pub async fn store(&self, duty: types::Duty, set: types::SignedDataSet) -> Result<(), Error> {
        let (response_tx, response_rx) = sync::oneshot::channel();
        let msg = Message::Store {
            duty,
            set,
            response: response_tx,
        };
        let _ = self.sender.send(msg).await;
        response_rx.await.unwrap()
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
        let (response_tx, response_rx) = sync::oneshot::channel();
        let msg = Message::WaitFor {
            duty,
            pub_key,
            response: response_tx,
        };
        let _ = self.sender.send(msg).await;
        response_rx.await.unwrap()
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
        let store = super::Handle::new(TestDeadliner::never());

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
        let store = super::Handle::new(deadliner);

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
        let store = super::Handle::new(TestDeadliner::never());

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
        let store = super::Handle::new(TestDeadliner::never());

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

        let store = super::Handle::new(deadliner);

        let duty = Duty::new_attester_duty(SlotNumber::new(1));
        let pub_key = PubKey::new([7u8; 48]);
        let first = MockSignedData(1);
        let second = MockSignedData(2);

        store
            .store(duty.clone(), first.singleton(pub_key))
            .await
            .unwrap();

        // The eviction task runs concurrently, so we wait until the specific
        // data is gone, so new readers are guaranteed to not observe it.
        evict_tx.send(duty.clone()).await.unwrap();
        // TODO: Find a better mechanism to wait for eviction
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
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

        let store = super::Handle::new(TestDeadliner::never());
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
        let store = super::Handle::new(TestDeadliner::never());

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
