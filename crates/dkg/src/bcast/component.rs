//! User-facing component handle and typed registry for reliable broadcast.

use std::{collections::HashMap, sync::Arc};

use futures::future::BoxFuture;
use libp2p::PeerId;
use prost::{Message, Name};
use prost_types::Any;
use tokio::sync::{RwLock, mpsc, oneshot};

use super::error::{Error, Result};

/// Typed message validator used for signature requests.
pub type CheckFn<M> = Box<dyn Fn(PeerId, &M) -> Result<()> + Send + Sync + 'static>;

/// Typed message callback invoked for validated broadcast messages.
///
/// The returned future is awaited by the inbound message handler, allowing
/// the callback to perform async operations (e.g. waiting for state that
/// becomes available later).
pub type CallbackFn<M> =
    Box<dyn Fn(PeerId, String, M) -> BoxFuture<'static, Result<()>> + Send + Sync + 'static>;

pub(crate) type Registry = Arc<RwLock<HashMap<String, Arc<dyn RegisteredMessage>>>>;
pub(crate) type BroadcastResultTx = oneshot::Sender<Result<()>>;

/// Broadcast command sent from the user-facing component into the swarm-owned
/// behaviour.
#[derive(Debug)]
pub(crate) struct BroadcastCommand {
    /// Registered message ID.
    pub(crate) msg_id: String,
    /// Wrapped protobuf message.
    pub(crate) any_msg: Any,
    /// Receives terminal broadcast result when requested by the caller.
    pub(crate) completion_tx: Option<BroadcastResultTx>,
}

/// Type-erased entry stored per registered message ID.
pub(crate) trait RegisteredMessage: Send + Sync {
    /// Validates the incoming wrapped protobuf message.
    fn check(&self, peer_id: PeerId, any: &Any) -> Result<()>;

    /// Dispatches the incoming wrapped protobuf message to the typed callback.
    fn callback(&self, peer_id: PeerId, msg_id: String, any: Any)
    -> BoxFuture<'static, Result<()>>;
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

    fn callback(
        &self,
        peer_id: PeerId,
        msg_id: String,
        any: Any,
    ) -> BoxFuture<'static, Result<()>> {
        match any.to_msg::<M>() {
            Ok(message) => (self.callback)(peer_id, msg_id, message),
            Err(e) => Box::pin(async move { Err(e.into()) }),
        }
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

    /// Registers a typed message ID before it is sent or received.
    ///
    /// `check` runs before this node signs an inbound signature request, and
    /// `callback` runs after a fully signed broadcast message is validated.
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

    /// Enqueues `msg` for reliable broadcast and returns after enqueue.
    ///
    /// Use this when the caller consumes [`super::Event`] separately or does
    /// not need to wait for terminal status. Use [`Self::broadcast_and_wait`]
    /// when the next protocol step depends on broadcast completion.
    pub async fn broadcast<M>(&self, msg_id: &str, msg: &M) -> Result<()>
    where
        M: Message + Name + Default + Clone + Send + Sync + 'static,
    {
        self.enqueue(msg_id, msg, None).await
    }

    /// Broadcasts `msg` and waits until the behaviour reports success or
    /// failure.
    ///
    /// Use this for protocol steps that must not continue after enqueue only.
    /// To make waiting cancellable, wrap this call in `tokio::select!`;
    /// dropping the returned future leaves the broadcast running and only
    /// drops this caller's completion notification.
    pub async fn broadcast_and_wait<M>(&self, msg_id: &str, msg: &M) -> Result<()>
    where
        M: Message + Name + Default + Clone + Send + Sync + 'static,
    {
        let (completion_tx, completion_rx) = oneshot::channel();
        self.enqueue(msg_id, msg, Some(completion_tx)).await?;
        completion_rx.await.map_err(|_| Error::BehaviourClosed)?
    }

    async fn enqueue<M>(
        &self,
        msg_id: &str,
        msg: &M,
        completion_tx: Option<BroadcastResultTx>,
    ) -> Result<()>
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
                completion_tx,
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
        p2p_context.set_local_peer_id(peer_id);
        let (_behaviour, component) = super::super::Behaviour::new(vec![peer_id], p2p_context, key);

        component
            .register_message::<prost_types::Timestamp>(
                "timestamp",
                Box::new(|_, _| Ok(())),
                Box::new(|_, _, _| Box::pin(async { Ok(()) })),
            )
            .await
            .unwrap();

        let error = component
            .register_message::<prost_types::Timestamp>(
                "timestamp",
                Box::new(|_, _| Ok(())),
                Box::new(|_, _, _| Box::pin(async { Ok(()) })),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, Error::DuplicateMessageId(_)));
    }
}
