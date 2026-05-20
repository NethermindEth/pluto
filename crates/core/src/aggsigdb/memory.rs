use tokio::sync::{Mutex, Notify};

use crate::types;
use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};

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

#[derive(Debug)]
struct MemDBInner {
    data: Mutex<HashMap<(types::Duty, types::PubKey), Box<dyn types::SignedData>>>,
    notify: Notify,
}

impl MemDB {
    /// Creates a new in-memory AggSigDB instance.
    pub fn new() -> Self {
        Self(Arc::new(MemDBInner {
            data: Mutex::new(HashMap::new()),
            notify: Notify::new(),
        }))
    }

    /// Stores aggregated signed duty data set.
    pub async fn store(
        &self,
        duty: types::Duty,
        pub_key: types::PubKey,
        signed_data: Box<dyn types::SignedData>,
    ) -> Result<(), Error> {
        let mut data = self.0.data.lock().await;

        match data.entry((duty, pub_key)) {
            Entry::Occupied(slot) if slot.get().as_ref() != signed_data.as_ref() => {
                Err(Error::MismatchingData)
            }
            Entry::Occupied(_) => Ok(()),
            Entry::Vacant(slot) => {
                slot.insert(signed_data);
                // TODO: Optimize to only wake those who are waiting for this specific duty and
                // pubkey
                self.0.notify.notify_waiters();
                Ok(())
            }
        }
    }

    /// Blocks and returns the aggregated signed duty data when available.
    pub async fn wait_for(
        &self,
        duty: types::Duty,
        pub_key: types::PubKey,
    ) -> Box<dyn types::SignedData> {
        let k = (duty, pub_key);
        loop {
            // Register interest before checking the map so that a concurrent `store` either
            // (a) inserts before we check and we observe the value, or (b) inserts after
            // our `notified()` is enabled and wakes us.
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            {
                let data = self.0.data.lock().await;
                if let Some(data) = data.get(&k) {
                    return data.clone();
                }
            }

            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        signeddata::SignedDataError,
        types::{Duty, PubKey, Signature, SignedData, SlotNumber},
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockSignedData;

    impl SignedData for MockSignedData {
        fn signature(&self) -> Result<Signature, SignedDataError> {
            Ok(Signature::new([42u8; 96]))
        }

        fn set_signature(&self, _signature: Signature) -> Result<Self, SignedDataError> {
            Ok(self.clone())
        }

        fn message_root(&self) -> Result<[u8; 32], SignedDataError> {
            Ok([42u8; 32])
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn store_and_wait() {
        let store = super::MemDB::new();
        let duty = Duty::new_attester_duty(SlotNumber::new(1));
        let pub_key = PubKey::new([7u8; 48]);
        let signed_data: Box<dyn SignedData> = Box::new(MockSignedData);

        let reader = {
            let store = store.clone();
            let duty = duty.clone();
            let pub_key = pub_key.clone();

            tokio::spawn(async move { store.wait_for(duty, pub_key).await })
        };

        // Give the reader a chance to reach `notified.await` before we store, so the
        // test actually exercises the notify wakeup path rather than the
        // fast-path lookup.
        tokio::task::yield_now().await;
        assert!(!reader.is_finished(), "wait_for should block until store");

        let write = store.store(duty, pub_key, signed_data.clone()).await;
        let read = reader.await.unwrap();

        assert!(write.is_ok());
        assert_eq!(read, signed_data);
    }
}
