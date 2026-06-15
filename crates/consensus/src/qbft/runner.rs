//! QBFT consensus runner bridge.

use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

use cancellation::CancellationTokenSource;
use crossbeam::channel as mpmc;
use prost::{Message, Name};
use prost_types::Any;
use tokio::{
    sync::mpsc,
    task::{JoinError, JoinSet},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

use crate::instance::{self, InstanceIo, RunnerError, RunnerResult};
use pluto_core::{
    corepb::v1::{core as pbcore, priority as pbpriority},
    deadline::AddOutcome,
    qbft,
    types::{Duty, DutyType},
};

use super::{
    component::Consensus,
    definition::{self, DecideCallback, DefinitionConfig},
    msg::{self, ConsensusQbftTypes},
    sniffer::Sniffer,
    transport,
};

// Only used while a bounded core channel is full; keep it low enough to resume
// promptly, but not a 1ms spin under sustained backpressure.
const BRIDGE_SEND_RETRY_INTERVAL: Duration = Duration::from_millis(10);

/// Runner result.
pub type Result<T> = std::result::Result<T, Error>;

/// Runner errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Duplicate proposal.
    #[error("propose consensus: {0}")]
    ProposeConsensus(#[source] instance::Error),

    /// Duplicate participation.
    #[error("participate consensus: {0}")]
    ParticipateConsensus(#[source] instance::Error),

    /// Input channel was full.
    #[error("input channel full")]
    InputChannelFull,

    /// Receiver ownership failed.
    #[error("{0}")]
    Instance(#[from] instance::Error),

    /// Value hashing failed.
    #[error("{0}")]
    Msg(#[from] msg::Error),

    /// Value packing failed.
    #[error("pack proto: {0}")]
    PackProto(#[source] prost::EncodeError),

    /// Blocking runner task failed.
    #[error("runner join: {0}")]
    Join(#[source] JoinError),

    /// Generic QBFT core returned a non-cancellation error.
    #[error("core qbft: {0}")]
    Core(#[source] qbft::QbftError),

    /// Transport failed while broadcasting or receiving.
    #[error("transport: {0}")]
    Transport(String),

    /// Running consensus instance finished without a decision.
    #[error("consensus timeout")]
    ConsensusTimeout,

    /// Running instance result channel closed before completion.
    #[error("runner result channel closed")]
    RunnerResultChannelClosed,

    /// Running instance completed with an error.
    #[error("runner result: {0}")]
    RunnerResult(#[source] RunnerError),
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RunnerResultError(String);

/// Proposes an unsigned duty data set into a QBFT instance.
pub(crate) async fn propose_unsigned(
    consensus: &Consensus,
    duty: Duty,
    value: pbcore::UnsignedDataSet,
    ct: &CancellationToken,
) -> Result<()> {
    propose(consensus, duty, value, ct).await
}

/// Proposes a priority protocol result into a QBFT instance.
pub(crate) async fn propose_priority(
    consensus: &Consensus,
    duty: Duty,
    value: pbpriority::PriorityResult,
    ct: &CancellationToken,
) -> Result<()> {
    propose(consensus, duty, value, ct).await
}

/// Hashes and packs the local value, then starts or joins the duty runner.
async fn propose<M>(
    consensus: &Consensus,
    duty: Duty,
    value: M,
    ct: &CancellationToken,
) -> Result<()>
where
    M: Message + Name + Clone + Send + Sync + 'static,
{
    let hash = msg::hash_proto(&value)?;
    let any = Any::from_msg(&value).map_err(Error::PackProto)?;
    let inst = consensus.get_instance_io(duty.clone());

    inst.mark_proposed().map_err(Error::ProposeConsensus)?;
    let value_closed = try_send_input(&inst.value_tx, any.clone())?.is_closed();
    let hash_closed = try_send_input(&inst.hash_tx, hash)?.is_closed();
    let verify_closed =
        consensus.compare_attestations() && try_send_input(&inst.verify_tx, any)?.is_closed();
    let input_closed = value_closed || hash_closed || verify_closed;

    if input_closed {
        if inst.has_started() {
            return wait_instance_result(&inst).await;
        }
        return Err(Error::InputChannelFull);
    }

    if !inst.maybe_start() {
        return wait_instance_result(&inst).await;
    }

    run_instance(consensus, duty, inst, ct).await
}

/// Starts participating in a duty without a local proposal value.
pub(crate) async fn participate(
    consensus: &Consensus,
    duty: Duty,
    ct: &CancellationToken,
) -> Result<()> {
    if matches!(
        duty.duty_type,
        DutyType::Aggregator | DutyType::SyncContribution
    ) {
        return Ok(());
    }

    if !pluto_featureset::GLOBAL_STATE
        .read()
        .expect("global feature set lock poisoned")
        .enabled(pluto_featureset::Feature::ConsensusParticipate)
    {
        return Ok(());
    }

    let inst = consensus.get_instance_io(duty.clone());
    inst.mark_participated()
        .map_err(Error::ParticipateConsensus)?;

    if !inst.maybe_start() {
        return Ok(());
    }

    run_instance(consensus, duty, inst, ct).await
}

/// Runs one consensus instance and publishes its completion result.
pub(crate) async fn run_instance(
    consensus: &Consensus,
    duty: Duty,
    inst: Arc<InstanceIo<msg::Msg>>,
    parent_ct: &CancellationToken,
) -> Result<()> {
    let result = run_instance_inner(consensus, duty.clone(), Arc::clone(&inst), parent_ct).await;
    let runner_result: RunnerResult = result
        .as_ref()
        .map_err(|err| Box::new(RunnerResultError(err.to_string())) as RunnerError)
        .copied();
    let _ = inst.err_tx.send(runner_result).await;

    result
}

/// Wires async component state into the generic blocking QBFT core.
async fn run_instance_inner(
    consensus: &Consensus,
    duty: Duty,
    inst: Arc<InstanceIo<msg::Msg>>,
    parent_ct: &CancellationToken,
) -> Result<()> {
    let nodes = consensus.node_count();
    let nodes_i64 = i64::try_from(nodes).expect("node count fits i64");
    let peer_idx = consensus.get_peer_idx();
    let peer_names = consensus.peer_names();
    let round_timer = consensus.round_timer(duty.clone());

    tracing::debug!(
        duty = %duty,
        peer = peer_idx,
        peers = ?consensus.peer_labels(),
        timer = round_timer.timer_type().as_str(),
        "QBFT consensus instance starting"
    );

    if consensus.add_deadline(duty.clone()).await != AddOutcome::Scheduled {
        tracing::warn!(duty = %duty, "Skipping consensus for expired duty");
        return Ok(());
    }

    let outer_rx = inst.take_recv_rx()?;
    let hash_rx = inst.take_hash_rx()?;
    let value_rx = inst.take_value_rx()?;
    let verify_rx = inst.take_verify_rx()?;

    let instance_ct = parent_ct.child_token();
    let core_cts = Arc::new(CancellationTokenSource::new());
    let core_ct = core_cts.token().clone();
    let decided = Arc::new(AtomicBool::new(false));
    let transport_error = Arc::new(Mutex::new(None::<String>));
    let runtime = tokio::runtime::Handle::current();

    let (inner_recv_tx, inner_recv_rx) = mpsc::channel(instance::RECV_BUFFER_SIZE);
    let (core_recv_tx, core_recv_rx) = mpmc::bounded(instance::RECV_BUFFER_SIZE);
    let (core_hash_tx, core_hash_rx) = mpmc::bounded(1);
    let (core_verify_tx, core_verify_rx) = mpmc::bounded(1);

    let transport = Arc::new(transport::Transport::new(
        transport_broadcaster(consensus.broadcaster()),
        consensus.privkey(),
        value_rx,
        inner_recv_tx,
        Sniffer::new(i64::try_from(nodes).expect("node count fits i64"), peer_idx),
    ));

    let mut tasks = JoinSet::new();
    tasks.spawn(bridge_mpsc_to_crossbeam(
        instance_ct.clone(),
        inner_recv_rx,
        core_recv_tx,
    ));
    tasks.spawn(bridge_mpsc_to_crossbeam(
        instance_ct.clone(),
        hash_rx,
        core_hash_tx,
    ));
    tasks.spawn(bridge_mpsc_to_crossbeam(
        instance_ct.clone(),
        verify_rx,
        core_verify_tx,
    ));

    {
        let transport = Arc::clone(&transport);
        let instance_ct = instance_ct.clone();
        let transport_error = Arc::clone(&transport_error);
        tasks.spawn(async move {
            if let Err(err) = transport.process_receives(instance_ct, outer_rx).await {
                *transport_error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Some(err.to_string());
            }
        });
    }

    {
        let instance_ct = instance_ct.clone();
        let core_cts = Arc::clone(&core_cts);
        tasks.spawn(async move {
            instance_ct.cancelled().await;
            core_cts.cancel();
        });
    }

    let decide_callback: DecideCallback = {
        let decided = Arc::clone(&decided);
        let duty = duty.clone();
        let instance_ct = instance_ct.clone();
        let core_cts = Arc::clone(&core_cts);
        Arc::new(move |qcommit| {
            let round = qcommit.first().map_or(0, |msg| msg.round());
            let leader_index = definition::leader(&duty, round, nodes_i64);
            let leader_name = usize::try_from(leader_index)
                .ok()
                .and_then(|index| peer_names.get(index))
                .map(String::as_str)
                .unwrap_or("unknown");
            tracing::debug!(
                duty = %duty.duty_type,
                slot = duty.slot.inner(),
                round,
                leader_index,
                leader_name,
                "QBFT consensus decided"
            );
            decided.store(true, Ordering::Relaxed);
            instance_ct.cancel();
            core_cts.cancel();
        })
    };

    let def = definition::new_definition(DefinitionConfig {
        nodes,
        subscribers: consensus.subscribers(),
        round_timer,
        decide_callback,
        compare_attestations: consensus.compare_attestations(),
        runtime: runtime.clone(),
    });

    let core_transport: qbft::Transport<ConsensusQbftTypes> = qbft::Transport {
        broadcast: Box::new({
            let transport = Arc::clone(&transport);
            let runtime = runtime.clone();
            let instance_ct = instance_ct.clone();
            let transport_error = Arc::clone(&transport_error);
            move |request: qbft::BroadcastRequest<'_, ConsensusQbftTypes>| {
                let justification = request.justification.cloned().unwrap_or_default();
                let result = runtime.block_on(transport.broadcast(transport::BroadcastRequest {
                    ct: instance_ct.clone(),
                    type_: request.type_,
                    duty: request.instance.clone(),
                    peer_idx: request.source,
                    round: request.round,
                    value_hash: *request.value,
                    prepared_round: request.prepared_round,
                    prepared_value_hash: *request.prepared_value,
                    justification,
                }));

                match result {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        *transport_error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner) = Some(err.to_string());
                        Err(qbft::QbftError::ContextCanceled)
                    }
                }
            }
        }),
        receive: core_recv_rx,
    };

    let core_ct_for_run = core_ct.clone();
    let core_result = tokio::task::spawn_blocking(move || {
        qbft::run(
            &core_ct_for_run,
            &def,
            &core_transport,
            &duty,
            peer_idx,
            core_hash_rx,
            core_verify_rx,
        )
    })
    .await;

    let canceled_before_teardown =
        parent_ct.is_cancelled() || instance_ct.is_cancelled() || core_ct.is_canceled();
    instance_ct.cancel();
    while let Some(result) = tasks.join_next().await {
        let _ = result;
    }

    let sniffer = consensus.sniffer();
    sniffer(transport.sniffer_instance());

    if let Some(err) = transport_error
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    {
        return Err(Error::Transport(err));
    }

    let core_result = core_result.map_err(Error::Join)?;

    match core_result {
        Ok(()) => Ok(()),
        Err(qbft::QbftError::ContextCanceled) if decided.load(Ordering::Relaxed) => Ok(()),
        Err(qbft::QbftError::ContextCanceled) => Err(Error::ConsensusTimeout),
        Err(qbft::QbftError::ChannelError(_)) if canceled_before_teardown => {
            Err(Error::ConsensusTimeout)
        }
        Err(err) => Err(Error::Core(err)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputSend {
    Sent,
    Closed,
}

impl InputSend {
    fn is_closed(self) -> bool {
        self == Self::Closed
    }
}

/// Sends a one-shot local input into an instance channel without waiting.
fn try_send_input<T>(tx: &mpsc::Sender<T>, value: T) -> Result<InputSend> {
    match tx.try_send(value) {
        Ok(()) => Ok(InputSend::Sent),
        Err(mpsc::error::TrySendError::Full(_)) => Err(Error::InputChannelFull),
        Err(mpsc::error::TrySendError::Closed(_)) => Ok(InputSend::Closed),
    }
}

/// Waits for an already-running instance to finish.
async fn wait_instance_result(inst: &InstanceIo<msg::Msg>) -> Result<()> {
    let mut err_rx = inst.take_err_rx()?;
    match err_rx.recv().await {
        Some(Ok(())) => Ok(()),
        Some(Err(err)) => Err(Error::RunnerResult(err)),
        None => Err(Error::RunnerResultChannelClosed),
    }
}

/// Bridges Tokio channels into the crossbeam channels expected by core QBFT.
async fn bridge_mpsc_to_crossbeam<T>(
    ct: CancellationToken,
    mut rx: mpsc::Receiver<T>,
    tx: mpmc::Sender<T>,
) where
    T: Send + 'static,
{
    loop {
        let value = tokio::select! {
            () = ct.cancelled() => return,
            value = rx.recv() => match value {
                Some(value) => value,
                None => return,
            },
        };

        send_to_crossbeam(&ct, &tx, value).await;
    }
}

async fn send_to_crossbeam<T>(ct: &CancellationToken, tx: &mpmc::Sender<T>, mut value: T) {
    loop {
        match tx.try_send(value) {
            Ok(()) | Err(mpmc::TrySendError::Disconnected(_)) => return,
            Err(mpmc::TrySendError::Full(returned)) => value = returned,
        }

        tokio::select! {
            () = ct.cancelled() => return,
            () = tokio::time::sleep(BRIDGE_SEND_RETRY_INTERVAL) => {}
        }
    }
}

/// Converts the component broadcaster into the transport broadcaster type.
fn transport_broadcaster(broadcaster: super::component::Broadcaster) -> transport::Broadcaster {
    Box::new(move |ct, msg| {
        let broadcaster = Arc::clone(&broadcaster);
        Box::pin(async move {
            broadcaster(ct, msg)
                .await
                .map_err(|err| transport::Error::Broadcast(err.to_string()))
        })
    })
}

#[cfg(test)]
mod tests {
    use std::{
        mem,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use pluto_featureset::{Config as FeatureConfig, Feature, FeatureSet, GLOBAL_STATE, Status};
    use prost::bytes::Bytes;
    use prost_types::Any;
    use tokio::sync::mpsc;

    use super::*;
    use crate::qbft::component::{self, Config};
    use pluto_core::{corepb::v1::core as pbcore, types::SlotNumber};

    #[tokio::test]
    async fn propose_when_instance_already_running_fills_value_hash_and_verify_channels() {
        let consensus = Arc::new(
            Consensus::new(Config {
                compare_attestations: true,
                peers: component::tests::peers(),
                ..component::tests::config_base(false)
            })
            .unwrap(),
        );
        let duty = component::tests::duty();
        let value = unsigned_value(0);
        let want_hash = msg::hash_proto(&value).unwrap();
        let want_any = Any::from_msg(&value).unwrap();
        let inst = consensus.get_instance_io(duty.clone());
        assert!(inst.maybe_start());
        let mut value_rx = inst.take_value_rx().unwrap();
        let mut hash_rx = inst.take_hash_rx().unwrap();
        let mut verify_rx = inst.take_verify_rx().unwrap();

        let task = {
            let consensus = Arc::clone(&consensus);
            let duty = duty.clone();
            let value = value.clone();
            tokio::spawn(async move {
                let ct = CancellationToken::new();
                consensus.propose(duty, value, &ct).await
            })
        };

        assert_eq!(recv_one(&mut value_rx).await, want_any);
        assert_eq!(recv_one(&mut hash_rx).await, want_hash);
        assert_eq!(recv_one(&mut verify_rx).await, want_any);
        inst.err_tx.send(Ok(())).await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn propose_rejects_duplicate_entrypoint() {
        let consensus = component::tests::consensus(0, true);
        let duty = component::tests::duty();
        let inst = consensus.get_instance_io(duty.clone());
        inst.mark_proposed().unwrap();

        let err = consensus
            .propose(duty, unsigned_value(0), &CancellationToken::new())
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "propose consensus: already proposed");
    }

    #[tokio::test]
    async fn propose_surfaces_full_input_channel() {
        let consensus = component::tests::consensus(0, true);
        let duty = component::tests::duty();
        let inst = consensus.get_instance_io(duty.clone());
        inst.value_tx.try_send(Any::default()).unwrap();

        let err = consensus
            .propose(duty, unsigned_value(0), &CancellationToken::new())
            .await
            .unwrap_err();

        assert!(matches!(err, Error::InputChannelFull));
    }

    #[tokio::test]
    async fn participate_skips_aggregator_and_sync_contribution() {
        let consensus = component::tests::consensus(0, true);
        let aggregator = Duty::new(SlotNumber::new(1), DutyType::Aggregator);
        let sync_contribution = Duty::new(SlotNumber::new(1), DutyType::SyncContribution);

        participate(&consensus, aggregator.clone(), &CancellationToken::new())
            .await
            .unwrap();
        participate(
            &consensus,
            sync_contribution.clone(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        assert!(
            consensus
                .get_instance_io(aggregator)
                .mark_participated()
                .is_ok()
        );
        assert!(
            consensus
                .get_instance_io(sync_contribution)
                .mark_participated()
                .is_ok()
        );
    }

    #[tokio::test]
    async fn participate_skips_when_feature_disabled() {
        let _featureset_guard = crate::qbft::FEATURESET_TEST_LOCK.lock().await;
        let consensus = component::tests::consensus(0, true);
        let duty = component::tests::duty();
        let _guard = FeatureSetGuard::new(FeatureConfig {
            disabled: vec![Feature::ConsensusParticipate],
            ..FeatureConfig::default()
        });

        participate(&consensus, duty.clone(), &CancellationToken::new())
            .await
            .unwrap();
        assert!(consensus.get_instance_io(duty).mark_participated().is_ok());
    }

    #[tokio::test]
    async fn participate_rejects_duplicate_entrypoint() {
        let _featureset_guard = crate::qbft::FEATURESET_TEST_LOCK.lock().await;
        let consensus = component::tests::consensus(0, true);
        let duty = component::tests::duty();
        let inst = consensus.get_instance_io(duty.clone());
        inst.mark_participated().unwrap();

        let err = participate(&consensus, duty, &CancellationToken::new())
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "participate consensus: already participated"
        );
    }

    #[tokio::test]
    async fn run_instance_sends_ok_result_when_deadline_is_not_scheduled() {
        let consensus = Consensus::new(Config {
            peers: component::tests::peers(),
            ..component::tests::config_base(true)
        })
        .unwrap();
        let duty = component::tests::duty();
        let inst = consensus.get_instance_io(duty.clone());
        let mut err_rx = inst.take_err_rx().unwrap();

        run_instance(&consensus, duty, inst, &CancellationToken::new())
            .await
            .unwrap();

        recv_one(&mut err_rx).await.unwrap();
    }

    #[tokio::test]
    async fn run_instance_cancels_and_emits_sniffer_on_teardown() {
        let sniffed = Arc::new(Mutex::new(Vec::new()));
        let consensus = Consensus::new(Config {
            peers: component::tests::peers(),
            sniffer: {
                let sniffed = Arc::clone(&sniffed);
                Arc::new(move |instance| sniffed.lock().unwrap().push(instance))
            },
            ..component::tests::config_base(false)
        })
        .unwrap();
        let duty = component::tests::duty();
        let inst = consensus.get_instance_io(duty.clone());
        let mut err_rx = inst.take_err_rx().unwrap();
        let ct = CancellationToken::new();
        ct.cancel();

        let err = run_instance(&consensus, duty, inst, &ct).await.unwrap_err();

        assert!(
            matches!(err, Error::ConsensusTimeout),
            "unexpected error: {err:?}"
        );
        let runner_err = recv_one(&mut err_rx).await.unwrap_err();
        assert_eq!(runner_err.to_string(), "consensus timeout");
        assert_eq!(sniffed.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn completed_participation_keeps_instance_for_late_propose() {
        let consensus = component::tests::consensus(0, true);
        let duty = component::tests::duty();
        let inst = consensus.get_instance_io(duty.clone());
        inst.mark_participated().unwrap();
        assert!(inst.maybe_start());
        let ct = CancellationToken::new();
        ct.cancel();

        let err = run_instance(&consensus, duty.clone(), Arc::clone(&inst), &ct)
            .await
            .unwrap_err();

        assert!(
            matches!(err, Error::ConsensusTimeout),
            "unexpected error: {err:?}"
        );
        let retained = consensus.get_instance_io(duty.clone());
        assert!(Arc::ptr_eq(&inst, &retained));
        assert!(retained.has_started());

        let err = consensus
            .propose(duty.clone(), unsigned_value(0), &CancellationToken::new())
            .await
            .unwrap_err();

        let Error::RunnerResult(source) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert_eq!(source.to_string(), "consensus timeout");
        assert!(source.source().is_none());
        assert!(Arc::ptr_eq(&retained, &consensus.get_instance_io(duty)));
    }

    #[tokio::test]
    async fn run_instance_parent_cancel_cancels_broadcast_token() {
        let (broadcast_started_tx, mut broadcast_started_rx) = mpsc::channel(1);
        let (broadcast_cancelled_tx, mut broadcast_cancelled_rx) = mpsc::channel(1);
        let consensus = Consensus::new(Config {
            peers: component::tests::peers(),
            broadcaster: Arc::new(move |ct, _| {
                let broadcast_started_tx = broadcast_started_tx.clone();
                let broadcast_cancelled_tx = broadcast_cancelled_tx.clone();
                Box::pin(async move {
                    let _ = broadcast_started_tx.send(()).await;
                    ct.cancelled().await;
                    let _ = broadcast_cancelled_tx.send(()).await;
                    Ok(())
                })
            }),
            ..component::tests::config_base(false)
        })
        .unwrap();
        let duty = Duty::new(SlotNumber::new(1), DutyType::Attester);
        let ct = CancellationToken::new();
        let task_ct = ct.clone();

        let task =
            tokio::spawn(async move { consensus.propose(duty, unsigned_value(0), &task_ct).await });

        recv_one(&mut broadcast_started_rx).await;
        ct.cancel();
        recv_one(&mut broadcast_cancelled_rx).await;
        let err = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("run instance timed out")
            .expect("task panicked")
            .unwrap_err();
        assert!(
            matches!(err, Error::ConsensusTimeout),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn bridge_stops_draining_when_core_channel_is_full() {
        let ct = CancellationToken::new();
        let (async_tx, async_rx) = mpsc::channel(1);
        let (core_tx, core_rx) = mpmc::bounded(1);
        core_tx.try_send(0).unwrap();
        async_tx.try_send(1).unwrap();
        let task = tokio::spawn(bridge_mpsc_to_crossbeam(ct.clone(), async_rx, core_tx));

        tokio::time::timeout(Duration::from_secs(1), async {
            let mut value = 2;
            loop {
                match async_tx.try_send(value) {
                    Ok(()) => return,
                    Err(mpsc::error::TrySendError::Full(returned)) => {
                        value = returned;
                        tokio::task::yield_now().await;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        panic!("async bridge input closed")
                    }
                }
            }
        })
        .await
        .expect("bridge did not take first async item");

        assert!(matches!(
            async_tx.try_send(3),
            Err(mpsc::error::TrySendError::Full(3))
        ));
        assert_eq!(core_rx.len(), 1);

        ct.cancel();
        drop(core_rx);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("bridge task did not stop")
            .expect("bridge task panicked");
    }

    async fn recv_one<T>(rx: &mut mpsc::Receiver<T>) -> T {
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("receiver timed out")
            .expect("receiver closed")
    }

    fn unsigned_value(seed: usize) -> pbcore::UnsignedDataSet {
        let mut set = std::collections::BTreeMap::new();
        set.insert(
            format!("validator-{seed}"),
            Bytes::from(format!("unsigned-{seed}")),
        );
        pbcore::UnsignedDataSet { set }
    }

    struct FeatureSetGuard {
        previous: Option<FeatureSet>,
    }

    impl FeatureSetGuard {
        fn new(config: FeatureConfig) -> Self {
            let replacement = FeatureSet::from_config(FeatureConfig {
                min_status: Status::Stable,
                ..config
            })
            .expect("test featureset is valid");
            let mut global = GLOBAL_STATE
                .write()
                .expect("global feature set lock poisoned");
            let previous = mem::replace(&mut *global, replacement);
            drop(global);

            Self {
                previous: Some(previous),
            }
        }
    }

    impl Drop for FeatureSetGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                *GLOBAL_STATE
                    .write()
                    .expect("global feature set lock poisoned") = previous;
            }
        }
    }
}
