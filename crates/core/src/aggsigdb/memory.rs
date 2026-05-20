use crate::types;
use std::collections::{HashMap, hash_map::Entry};

#[derive(Debug, thiserror::Error)]
enum StoreError {
    #[error("Mismatching data")]
    MismatchingData,

    #[error("Send error: {0}")]
    Send(#[from] tokio::sync::mpsc::error::SendError<MemDBCommand>),

    #[error("Recv error: {0}")]
    Recv(#[from] tokio::sync::oneshot::error::RecvError),
}

#[derive(Debug)]
enum MemDBCommand {
    Store {
        duty: types::Duty,
        pub_key: types::PubKey,
        signed_data: Box<dyn types::SignedData>,

        response: tokio::sync::oneshot::Sender<Result<(), StoreError>>,
    },
}

#[derive(Debug)]
struct MemDBActor {
    receiver: tokio::sync::mpsc::Receiver<MemDBCommand>,
    data: HashMap<(types::Duty, types::PubKey), Box<dyn types::SignedData>>,
}

impl MemDBActor {
    fn new(receiver: tokio::sync::mpsc::Receiver<MemDBCommand>) -> Self {
        Self {
            receiver,
            data: HashMap::new(),
        }
    }

    async fn run(&mut self) {
        while let Some(cmd) = self.receiver.recv().await {
            match cmd {
                MemDBCommand::Store {
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
    ) -> Result<(), StoreError> {
        // TODO: Add deadline tracking
        // _ = db.deadliner.Add(command.duty)

        match self.data.entry((duty, pub_key)) {
            Entry::Occupied(slot) if slot.get().as_ref() != signed_data.as_ref() => {
                Err(StoreError::MismatchingData)
            }
            Entry::Occupied(_) => Ok(()),
            Entry::Vacant(slot) => {
                slot.insert(signed_data);
                Ok(())
            }
        }
    }
}

struct MemDBHandle {
    sender: tokio::sync::mpsc::Sender<MemDBCommand>,
}

impl MemDBHandle {
    fn new() -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(100);
        let mut actor = MemDBActor::new(receiver);
        // TODO: Pass a cancellation token
        tokio::spawn(async move {
            actor.run().await;
        });
        Self { sender }
    }

    async fn store(
        &self,
        duty: types::Duty,
        pub_key: types::PubKey,
        signed_data: Box<dyn types::SignedData>,
    ) -> Result<(), StoreError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.sender
            .send(MemDBCommand::Store {
                duty,
                pub_key,
                signed_data,
                response: tx,
            })
            .await?;
        rx.await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let handle = MemDBHandle::new();
        let duty = Duty::new_attester_duty(SlotNumber::new(1));
        let pub_key = PubKey::new([7u8; 48]);
        let signed_data: Box<dyn SignedData> = Box::new(MockSignedData);

        let task = tokio::spawn(async move { handle.store(duty, pub_key, signed_data).await });

        task.await
            .expect("store task panicked")
            .expect("store returned an error");
    }
}
