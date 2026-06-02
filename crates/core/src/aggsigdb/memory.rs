use crate::{
    aggsigdb::types::{AggSigDB, Error},
    deadline, types,
};
use std::collections::{HashMap, hash_map::Entry};
use tokio::sync;
use tokio_util::sync::CancellationToken;

type Waiters =
    HashMap<(types::Duty, types::PubKey), Vec<sync::oneshot::Sender<Box<dyn types::SignedData>>>>;

struct MemoryDBActor {
    entries: HashMap<types::Duty, HashMap<types::PubKey, Box<dyn types::SignedData>>>,
    waiters: Waiters,
    deadliner: deadline::DeadlinerHandle,
}

impl MemoryDBActor {
    async fn run(
        &mut self,
        mut messages_rx: sync::mpsc::Receiver<Message>,
        mut expired_rx: sync::mpsc::Receiver<types::Duty>,
        ct: CancellationToken,
    ) {
        loop {
            tokio::select! {
                biased; // We want to evaluate expirations first

                _ = ct.cancelled() => break, // Stop the actor when the cancellation token is triggered.

                Some(duty) = expired_rx.recv() => self.evict(duty),

                msg = messages_rx.recv() => match msg {
                    None => break, // Stop the actor when all handles have been dropped.
                    Some(msg) => match msg {
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
                    }
                }
            }

            // After each message, trim waiters in case that the futures are dropped.
            self.trim_readers();
        }
    }

    async fn store(&mut self, duty: types::Duty, set: types::SignedDataSet) -> Result<(), Error> {
        if set.is_empty() {
            return Ok(());
        }

        // TODO(charon): Distinguish between no deadline supported vs already expired.
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
                            if !w.is_closed() {
                                let _ = w.send(signed_data.clone());
                            }
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

    fn trim_readers(&mut self) {
        self.waiters.retain(|_, waiters| {
            waiters.retain(|w| !w.is_closed());

            !waiters.is_empty()
        });
    }
}

enum Message {
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
pub struct MemoryDBHandle {
    sender: sync::mpsc::Sender<Message>,
}

impl MemoryDBHandle {
    /// Creates a new in-memory AggSigDB instance, and get a handle to it.
    ///
    /// The underlying instance gets dropped when all handles are dropped.
    pub fn new(
        deadliner: deadline::DeadlinerHandle,
        expired_rx: sync::mpsc::Receiver<types::Duty>,
        ct: CancellationToken,
    ) -> Self {
        let (sender, receiver) = sync::mpsc::channel(100);
        let mut actor = MemoryDBActor {
            entries: HashMap::new(),
            waiters: HashMap::new(),
            deadliner,
        };

        tokio::spawn(async move { actor.run(receiver, expired_rx, ct).await });

        Self { sender }
    }
}

#[async_trait::async_trait]
impl AggSigDB for MemoryDBHandle {
    async fn store(&self, duty: types::Duty, set: types::SignedDataSet) -> Result<(), Error> {
        let (response_tx, response_rx) = sync::oneshot::channel();
        let msg = Message::Store {
            duty,
            set,
            response: response_tx,
        };
        self.sender.send(msg).await.map_err(|_| Error::Terminated)?;
        response_rx.await.map_err(|_| Error::Terminated)?
    }

    async fn wait_for(
        &self,
        duty: types::Duty,
        pub_key: types::PubKey,
    ) -> Result<Box<dyn types::SignedData>, Error> {
        let (response_tx, response_rx) = sync::oneshot::channel();
        let msg = Message::WaitFor {
            duty,
            pub_key,
            response: response_tx,
        };
        self.sender.send(msg).await.map_err(|_| Error::Terminated)?;
        response_rx.await.map_err(|_| Error::Terminated)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aggsigdb::{
            memory::MemoryDBHandle,
            types::{AggSigDB, Error},
        },
        deadline,
        signeddata::SignedDataError,
        types::{Duty, PubKey, Signature, SignedData, SignedDataSet, SlotNumber},
    };
    use tokio::sync;
    use tokio_util::sync::CancellationToken;

    /// Some mock signed data type for testing.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockSignedData(u8);

    impl SignedData for MockSignedData {
        fn signature(&self) -> Result<Signature, SignedDataError> {
            Ok([self.0; 96])
        }

        fn set_signature(&self, _signature: Signature) -> Result<Self, SignedDataError> {
            Ok(self.clone())
        }

        fn set_signature_boxed(
            &self,
            signature: Signature,
        ) -> Result<Box<dyn SignedData>, SignedDataError> {
            Ok(Box::new(self.set_signature(signature)?))
        }

        fn message_root(&self) -> Result<[u8; 32], SignedDataError> {
            Ok([self.0; 32])
        }
    }

    impl MockSignedData {
        fn singleton(&self, pub_key: PubKey) -> SignedDataSet {
            let mut set = SignedDataSet::new();
            set.insert(pub_key, self.boxed());
            set
        }

        fn boxed(&self) -> Box<dyn SignedData> {
            Box::new(self.clone())
        }
    }

    /// Create a test deadline handle and an expiration channel.
    fn test_deadline() -> (
        sync::mpsc::Sender<Duty>,
        deadline::DeadlinerHandle,
        sync::mpsc::Receiver<Duty>,
    ) {
        let (tx, rx) = sync::mpsc::channel(1);
        let deadliner = deadline::DeadlinerHandle::always(deadline::AddOutcome::Scheduled);

        (tx, deadliner, rx)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_read() {
        let (_, deadliner, expiration_rx) = test_deadline();
        let store = MemoryDBHandle::new(deadliner, expiration_rx, CancellationToken::new());

        let duty = Duty::new_proposer_duty(SlotNumber::new(10));
        let pub_key = PubKey::new([7u8; 48]);
        let signed_data = MockSignedData(42);

        store
            .store(duty.clone(), signed_data.singleton(pub_key))
            .await
            .unwrap();

        let result = store.wait_for(duty, pub_key).await.unwrap();
        assert_eq!(result, signed_data.boxed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_unblocks() {
        let (_, deadliner, expiration_rx) = test_deadline();
        let store = MemoryDBHandle::new(deadliner, expiration_rx, CancellationToken::new());

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
        let read = reader.await.unwrap().unwrap();

        assert!(write.is_ok());
        assert_eq!(read, signed_data.boxed());
    }

    #[tokio::test]
    async fn write_while_cancelled() {
        let ct = CancellationToken::new();

        let (_, deadliner, expiration_rx) = test_deadline();
        let store = MemoryDBHandle::new(deadliner, expiration_rx, ct.clone());

        let duty = Duty::new_proposer_duty(SlotNumber::new(10));
        let pub_key = PubKey::new([7u8; 48]);
        let signed_data = MockSignedData(42);

        ct.cancel();

        let res = store.store(duty, signed_data.singleton(pub_key)).await;
        assert!(matches!(res, Err(Error::Terminated)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cannot_overwrite() {
        let (_, deadliner, expiration_rx) = test_deadline();
        let store = MemoryDBHandle::new(deadliner, expiration_rx, CancellationToken::new());

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
        let (_, deadliner, expiration_rx) = test_deadline();
        let store = MemoryDBHandle::new(deadliner, expiration_rx, CancellationToken::new());

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

        let result = store.wait_for(duty, pub_key).await.unwrap();
        assert_eq!(result, signed_data.boxed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_evict_wait_then_write() {
        let (expiration_tx, deadliner, expiration_rx) = test_deadline();

        let store = MemoryDBHandle::new(deadliner.clone(), expiration_rx, CancellationToken::new());

        let duty = Duty::new_attester_duty(SlotNumber::new(1));
        let pub_key = PubKey::new([7u8; 48]);
        let first = MockSignedData(1);
        let second = MockSignedData(2);

        store
            .store(duty.clone(), first.singleton(pub_key))
            .await
            .unwrap();

        // Queue the expiration. Immediately run a dummy store, and by the time it
        // compeltes we know that the expiration has been processed.
        expiration_tx.send(duty.clone()).await.unwrap();
        {
            let dummy = Duty::new_attester_duty(SlotNumber::new(u64::MAX));
            store
                .store(dummy, MockSignedData(0).singleton(pub_key))
                .await
                .unwrap();
        }

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

        let read = reader.await.unwrap().unwrap();
        assert_eq!(read, second.boxed());
        assert_ne!(read, first.boxed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn write_unblocks_many() {
        const N: usize = 4;

        let (_, deadliner, expiration_rx) = test_deadline();
        let store = MemoryDBHandle::new(deadliner, expiration_rx, CancellationToken::new());
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
            let read = reader.await.unwrap().unwrap();
            assert_eq!(read, signed_data.boxed());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unrelated_write_does_not_unblock() {
        let (_, deadliner, expiration_rx) = test_deadline();
        let store = MemoryDBHandle::new(deadliner, expiration_rx, CancellationToken::new());

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

        // Storing an unrelated key does not affect readers.
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

        let read = reader.await.unwrap().unwrap();
        assert_eq!(read, data_a.boxed());
        assert_ne!(read, data_b.boxed());
    }
}
