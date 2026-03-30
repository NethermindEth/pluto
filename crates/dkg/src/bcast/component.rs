//! User-facing component handle and typed registry for reliable broadcast.

use std::{collections::HashMap, sync::Arc};

use libp2p::PeerId;
use prost::{Message, Name};
use prost_types::Any;
use tokio::sync::{RwLock, mpsc};

use super::error::{Error, Result};

/// Typed message validator used for signature requests.
pub type CheckFn<M> = Box<dyn Fn(PeerId, &M) -> Result<()> + Send + Sync + 'static>;

/// Typed message callback invoked for validated broadcast messages.
pub type CallbackFn<M> = Box<dyn Fn(PeerId, &str, M) -> Result<()> + Send + Sync + 'static>;

pub(crate) type Registry = Arc<RwLock<HashMap<String, Arc<dyn RegisteredMessage>>>>;

/// Broadcast command sent from the user-facing component into the swarm-owned
/// behaviour.
#[derive(Debug)]
pub(crate) struct BroadcastCommand {
    /// Registered message ID.
    pub(crate) msg_id: String,
    /// Wrapped protobuf message.
    pub(crate) any_msg: Any,
}

/// Type-erased entry stored per registered message ID.
pub(crate) trait RegisteredMessage: Send + Sync {
    /// Validates the incoming wrapped protobuf message.
    fn check(&self, peer_id: PeerId, any: &Any) -> Result<()>;

    /// Dispatches the incoming wrapped protobuf message to the typed callback.
    fn callback(&self, peer_id: PeerId, msg_id: &str, any: &Any) -> Result<()>;
}

struct TypedRegistration<M> {
    check: CheckFn<M>,
    callback: CallbackFn<M>,
}

impl<M> RegisteredMessage for TypedRegistration<M>
where
    M: Message + Name + Default + Clone + Send + Sync + 'static,
{
    fn check(&self, peer_id: PeerId, any: &Any) -> Result<()> {
        let message = any.to_msg::<M>()?;
        (self.check)(peer_id, &message)
    }

    fn callback(&self, peer_id: PeerId, msg_id: &str, any: &Any) -> Result<()> {
        let message = any.to_msg::<M>()?;
        (self.callback)(peer_id, msg_id, message)
    }
}

/// User-facing handle for DKG reliable broadcast.
#[derive(Clone)]
pub struct Component {
    command_tx: mpsc::UnboundedSender<BroadcastCommand>,
    registry: Registry,
}

impl Component {
    pub(crate) fn new(
        command_tx: mpsc::UnboundedSender<BroadcastCommand>,
        registry: Registry,
    ) -> Self {
        Self {
            command_tx,
            registry,
        }
    }

    /// Registers a typed message ID with its validator and callback.
    pub async fn register_message<M>(
        &self,
        msg_id: impl Into<String>,
        check: CheckFn<M>,
        callback: CallbackFn<M>,
    ) -> Result<()>
    where
        M: Message + Name + Default + Clone + Send + Sync + 'static,
    {
        let msg_id = msg_id.into();
        let mut registry = self.registry.write().await;

        if registry.contains_key(&msg_id) {
            return Err(Error::DuplicateMessageId(msg_id));
        }

        registry.insert(msg_id, Arc::new(TypedRegistration::<M> { check, callback }));

        Ok(())
    }

    /// Enqueues the provided message for broadcast to all configured peers.
    ///
    /// Completion is reported asynchronously through [`super::Event`].
    pub async fn broadcast<M>(&self, msg_id: &str, msg: &M) -> Result<()>
    where
        M: Message + Name + Default + Clone + Send + Sync + 'static,
    {
        let any_msg = Any::from_msg(msg)?;
        if !self.registry.read().await.contains_key(msg_id) {
            return Err(Error::UnknownMessageId(msg_id.to_string()));
        }

        self.command_tx
            .send(BroadcastCommand {
                msg_id: msg_id.to_string(),
                any_msg,
            })
            .map_err(|_| Error::BehaviourClosed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pluto_p2p::peer::peer_id_from_key;
    use pluto_testutil::random::generate_insecure_k1_key;

    use super::*;

    #[tokio::test]
    async fn duplicate_message_id_registration_fails() {
        let key = generate_insecure_k1_key(1);
        let peer_id = peer_id_from_key(key.public_key()).unwrap();
        let p2p_context = pluto_p2p::p2p_context::P2PContext::new(vec![peer_id]);
        let (_behaviour, component) =
            super::super::Behaviour::new(peer_id, vec![peer_id], p2p_context, key);

        component
            .register_message::<prost_types::Timestamp>(
                "timestamp",
                Box::new(|_, _| Ok(())),
                Box::new(|_, _, _| Ok(())),
            )
            .await
            .unwrap();

        let error = component
            .register_message::<prost_types::Timestamp>(
                "timestamp",
                Box::new(|_, _| Ok(())),
                Box::new(|_, _, _| Ok(())),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, Error::DuplicateMessageId(_)));
    }
}
