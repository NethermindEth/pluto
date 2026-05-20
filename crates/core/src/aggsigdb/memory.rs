use crate::types;
use std::collections::{HashMap, hash_map::Entry};

/// Errors for the in-memory AggSigDB implementation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Data for the same duty and public key already exists but does not match
    /// the new data.
    #[error("Mismatching data")]
    MismatchingData,
}

#[derive(Debug)]
enum Command {
    Store {
        duty: types::Duty,
        pub_key: types::PubKey,
        signed_data: Box<dyn types::SignedData>,

        response: tokio::sync::oneshot::Sender<Result<(), Error>>,
    },
}

#[derive(Debug)]
struct Actor {
    receiver: tokio::sync::mpsc::Receiver<Command>,
    data: HashMap<(types::Duty, types::PubKey), Box<dyn types::SignedData>>,
}

impl Actor {
    fn new(receiver: tokio::sync::mpsc::Receiver<Command>) -> Self {
        Self {
            receiver,
            data: HashMap::new(),
        }
    }

    async fn run(&mut self) {
        while let Some(cmd) = self.receiver.recv().await {
            match cmd {
                Command::Store {
                    duty,
                    pub_key,
                    signed_data,
                    response,
                } => {
                    let result = self.store(duty, pub_key, signed_data).await;
                    let _ = response.send(result);
                }
            }
        }
    }

    async fn store(
        &mut self,
        duty: types::Duty,
        pub_key: types::PubKey,
        signed_data: Box<dyn types::SignedData>,
    ) -> Result<(), Error> {
        // TODO: Add deadline tracking
        // _ = db.deadliner.Add(command.duty)

        match self.data.entry((duty, pub_key)) {
            Entry::Occupied(slot) if slot.get().as_ref() != signed_data.as_ref() => {
                Err(Error::MismatchingData)
            }
            Entry::Occupied(_) => Ok(()),
            Entry::Vacant(slot) => {
                slot.insert(signed_data);
                Ok(())
            }
        }
    }
}

/// Handle to interact with the AggSigDB in-memory actor.
#[derive(Clone)]
pub struct Handle {
    sender: tokio::sync::mpsc::Sender<Command>,
}

impl Handle {
    fn new() -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(100);
        let mut actor = Actor::new(receiver);
        tokio::spawn(async move {
            actor.run().await;
        });
        Self { sender }
    }

    /// Stores aggregated signed duty data set.
    pub async fn store(
        &self,
        duty: types::Duty,
        pub_key: types::PubKey,
        signed_data: Box<dyn types::SignedData>,
    ) -> Result<(), Error> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self
            .sender
            .send(Command::Store {
                duty,
                pub_key,
                signed_data,
                response: tx,
            })
            .await;
        rx.await.expect("Actor task has been killed")
    }
}

/// Create a new memory AggSigDB implementation and return its handle.
///
/// Clone this handle to share access to the same AggSigDB instance across
/// multiple tasks.
pub fn new() -> Handle {
    Handle::new()
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

    #[tokio::test]
    async fn test_single_handle_store() {
        let handle = super::new();
        let duty = Duty::new_attester_duty(SlotNumber::new(1));
        let pub_key = PubKey::new([7u8; 48]);
        let signed_data: Box<dyn SignedData> = Box::new(MockSignedData);

        let task = tokio::spawn(async move { handle.store(duty, pub_key, signed_data).await });

        task.await
            .expect("store task panicked")
            .expect("store returned an error");
    }
}
