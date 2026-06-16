use std::{
    collections::{BTreeMap, HashMap, HashSet, hash_map::Entry},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use pluto_core::{
    corepb::v1::{consensus as pbconsensus, core as pbcore},
    qbft,
    types::{Duty, DutyType, SlotNumber},
};
use prost::bytes::Bytes;
use tokio::{sync::mpsc, task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

use super::{
    Peer,
    component::{self, Config, Consensus},
};
use crate::timer::{
    INC_ROUND_INCREASE, INC_ROUND_START, LINEAR_ROUND_INC, RoundTimer, RoundTimerFunc,
    RoundTimerFuture, TimerType,
};

const SIM_TIMEOUT: Duration = Duration::from_secs(12);
const TICK: Duration = Duration::from_millis(10);
const DISABLED: Duration = Duration::from_secs(999 * 60 * 60);

#[tokio::test(start_paused = true)]
async fn strategy_simulator_once() {
    let results = run_strategy_simulator(SimConfig {
        label: None,
        seed: 0,
        latency_jitter: Duration::from_millis(50),
        latency_per_peer: BTreeMap::from([
            (0, Duration::from_millis(100)),
            (1, Duration::from_millis(100)),
            (2, Duration::from_millis(100)),
            (3, Duration::from_millis(100)),
        ]),
        start_by_peer: BTreeMap::new(),
        timer_strategy: TimerStrategy::Increasing,
        timeout: SIM_TIMEOUT,
    })
    .await;

    assert_eq!(results.len(), 4);
    assert!(
        !is_undecided(&results),
        "expected all peers to decide: {results:?}"
    );
}

#[ignore = "diagnostic matrix is intentionally skipped by default"]
#[tokio::test(start_paused = true)]
async fn strategy_simulator_matrix() {
    let configs = matrix_configs(1);
    assert!(!configs.is_empty());

    let total_configs = configs.len();
    let mut summaries = BTreeMap::<MatrixKey, MatrixSummary>::new();
    for (index, config) in configs.into_iter().enumerate() {
        let peer_count = config.latency_per_peer.len();
        let label = config.label.expect("matrix config has label");
        let key = MatrixKey {
            size: label.size,
            distribution: label.distribution,
            timer: config.timer_strategy.name(),
        };
        let results = run_strategy_simulator(config).await;
        assert_eq!(results.len(), peer_count);

        let summary = summaries.entry(key).or_default();
        summary.total = summary
            .total
            .checked_add(1)
            .expect("matrix summary total fits usize");
        if is_undecided(&results) {
            summary.undecided = summary
                .undecided
                .checked_add(1)
                .expect("matrix summary undecided count fits usize");
        } else {
            summary.durations.push(quorum_decided_duration(&results));
            summary.rounds.push(decided_round(&results));
        }

        let completed = index
            .checked_add(1)
            .expect("matrix config index increments");
        if completed.checked_rem(100).expect("non-zero divisor") == 0 {
            println!("Completed {completed}/{total_configs}");
        }
    }

    print_matrix_summaries(&summaries);
    print_timer_aggregates(&summaries);
}

#[tokio::test(start_paused = true)]
async fn strategy_exp_timer_smoke() {
    let timer = StrategyRoundTimer::new(TimerStrategy::Exp {
        base: LINEAR_ROUND_INC,
    });

    for round in 1..5 {
        let timeout = timer.timer(round).expect("timer constructs");
        drop(timeout);
    }
}

#[derive(Debug, Clone)]
struct SimConfig {
    label: Option<MatrixLabel>,
    seed: u64,
    latency_jitter: Duration,
    latency_per_peer: BTreeMap<usize, Duration>,
    start_by_peer: BTreeMap<usize, Duration>,
    timer_strategy: TimerStrategy,
    timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
struct MatrixLabel {
    size: &'static str,
    distribution: &'static str,
}

#[derive(Debug, Default)]
struct MatrixSummary {
    total: usize,
    undecided: usize,
    rounds: Vec<i64>,
    durations: Vec<Duration>,
}

impl MatrixSummary {
    fn undecided_percent(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }

        100.0 * f64_from_usize(self.undecided) / f64_from_usize(self.total)
    }

    fn avg_round(&self) -> f64 {
        if self.rounds.is_empty() {
            return 0.0;
        }

        self.rounds.iter().copied().map(f64_from_i64).sum::<f64>()
            / f64_from_usize(self.rounds.len())
    }

    fn avg_duration(&self) -> Duration {
        if self.durations.is_empty() {
            return Duration::ZERO;
        }

        let total = self
            .durations
            .iter()
            .copied()
            .fold(Duration::ZERO, |sum, duration| {
                sum.checked_add(duration)
                    .expect("test matrix duration sum fits Duration")
            });
        total
            .checked_div(u32::try_from(self.durations.len()).expect("duration count fits u32"))
            .expect("non-empty duration count")
    }

    fn stddev_duration(&self) -> Duration {
        if self.durations.is_empty() {
            return Duration::ZERO;
        }

        let mean = self.avg_duration().as_secs_f64();
        let variance = self
            .durations
            .iter()
            .map(|duration| {
                let diff = duration.as_secs_f64() - mean;
                diff * diff
            })
            .sum::<f64>()
            / f64_from_usize(self.durations.len());

        Duration::from_secs_f64(variance.sqrt())
    }
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MatrixKey {
    size: &'static str,
    distribution: &'static str,
    timer: String,
}

#[derive(Debug, Clone, Copy)]
enum TimerStrategy {
    Increasing,
    Exp { base: Duration },
    ExpDouble { base: Duration },
    Linear { base: Duration },
    LinearDouble { base: Duration },
}

impl TimerStrategy {
    fn duration(self, round: i64) -> Duration {
        let round = u32::try_from(round).expect("test round fits u32");
        match self {
            Self::Increasing => INC_ROUND_START
                .checked_add(
                    INC_ROUND_INCREASE
                        .checked_mul(round)
                        .expect("test increasing timer increment fits"),
                )
                .expect("test increasing timer duration fits"),
            Self::Exp { base } | Self::ExpDouble { base } => {
                let exponent = round.checked_sub(1).expect("test round is positive");
                let multiplier = 2u32
                    .checked_pow(exponent)
                    .expect("test exp timer multiplier fits u32");
                base.checked_mul(multiplier)
                    .expect("test exp timer duration fits")
            }
            Self::Linear { base } | Self::LinearDouble { base } => base
                .checked_mul(round)
                .expect("test linear timer duration fits"),
        }
    }

    fn double(self) -> bool {
        matches!(self, Self::ExpDouble { .. } | Self::LinearDouble { .. })
    }

    fn timer_type(self) -> TimerType {
        match self {
            Self::Increasing => TimerType::Increasing,
            Self::Exp { .. }
            | Self::ExpDouble { .. }
            | Self::Linear { .. }
            | Self::LinearDouble { .. } => TimerType::EagerDoubleLinear,
        }
    }

    fn name(self) -> String {
        match self {
            Self::Increasing => "increasing".to_owned(),
            Self::Exp { base } => format!("exp_{}", base.as_millis()),
            Self::ExpDouble { base } => format!("edouble_{}", base.as_millis()),
            Self::Linear { base } => format!("linear_{}", base.as_millis()),
            Self::LinearDouble { base } => format!("ldouble_{}", base.as_millis()),
        }
    }
}

#[derive(Debug, Clone)]
struct SimResult {
    peer_idx: usize,
    decided: bool,
    round: Option<i64>,
    duration: Option<Duration>,
}

async fn run_strategy_simulator(config: SimConfig) -> Vec<SimResult> {
    let peer_count = config.latency_per_peer.len();
    let (round_tx, mut round_rx) = mpsc::unbounded_channel();
    let network = SimNetwork::new(peer_count, &config, round_tx);
    let duty = Duty::new(SlotNumber::new(config.seed), DutyType::Attester);
    let ct = CancellationToken::new();
    let (decided_tx, mut decided_rx) = mpsc::unbounded_channel();
    let start = Instant::now();

    for (peer_idx, node) in network.nodes().iter().enumerate() {
        let decided_tx = decided_tx.clone();
        node.subscribe(move |_, _| {
            let _ = decided_tx.send((peer_idx, start.elapsed()));
            Ok(())
        });
    }
    drop(decided_tx);

    let mut tasks = JoinSet::new();
    for (peer_idx, node) in network.nodes().iter().enumerate() {
        let start_delay = config
            .start_by_peer
            .get(&peer_idx)
            .copied()
            .unwrap_or_default();
        if start_delay == DISABLED {
            continue;
        }

        let node = Arc::clone(node);
        let duty = duty.clone();
        let ct = ct.clone();
        tasks.spawn(async move {
            if !start_delay.is_zero() {
                tokio::time::sleep(start_delay).await;
            }
            let result = node.propose(duty, unsigned_value(peer_idx), &ct).await;
            (peer_idx, result)
        });
    }

    simulator_gosched().await;
    network.process_buffer().await;

    let mut results = (0..peer_count)
        .map(|peer_idx| SimResult {
            peer_idx,
            decided: false,
            round: None,
            duration: None,
        })
        .collect::<Vec<_>>();

    while start.elapsed() < config.timeout && !all_started_peers_decided(&results, &config) {
        network.process_buffer().await;
        simulator_gosched().await;
        drain_decisions(&mut decided_rx, &mut results);

        if all_started_peers_decided(&results, &config) {
            break;
        }

        tokio::time::advance(TICK).await;
        simulator_gosched().await;
        network.process_buffer().await;
        simulator_gosched().await;
    }

    drain_decisions(&mut decided_rx, &mut results);

    ct.cancel();
    network.cancel();
    while let Some(joined) = tasks.join_next().await {
        let (_peer_idx, result) = joined.expect("strategy simulator task panicked");
        if let Err(err) = result {
            assert!(
                matches!(err, super::runner::Error::ConsensusTimeout),
                "unexpected simulator error: {err}"
            );
        }
    }

    while let Ok((peer_idx, round)) = round_rx.try_recv() {
        if let Some(result) = results.get_mut(peer_idx) {
            result.round = Some(round);
        }
    }

    results
}

fn is_undecided(results: &[SimResult]) -> bool {
    let decided = results.iter().filter(|result| result.decided).count();
    decided < quorum(results.len())
}

fn quorum(nodes: usize) -> usize {
    nodes
        .checked_mul(2)
        .and_then(|nodes| nodes.checked_add(2))
        .and_then(|nodes| nodes.checked_div(3))
        .expect("test node count permits quorum calculation")
}

fn drain_decisions(
    decided_rx: &mut mpsc::UnboundedReceiver<(usize, Duration)>,
    results: &mut [SimResult],
) {
    while let Ok((peer_idx, duration)) = decided_rx.try_recv() {
        if let Some(result) = results.get_mut(peer_idx) {
            result.decided = true;
            result.duration = Some(duration);
        }
    }
}

fn decided_round(results: &[SimResult]) -> i64 {
    results
        .iter()
        .find(|result| result.decided)
        .and_then(|result| result.round)
        .expect("decided result has sniffed commit round")
}

fn quorum_decided_duration(results: &[SimResult]) -> Duration {
    let mut durations = results
        .iter()
        .filter(|result| result.decided)
        .map(|result| result.duration.expect("decided result has duration"))
        .collect::<Vec<_>>();
    assert!(
        durations.len() >= quorum(results.len()),
        "not enough decided durations"
    );

    durations.sort();
    let quorum_index = quorum(results.len())
        .checked_sub(1)
        .expect("quorum for non-empty results is positive");
    durations[quorum_index]
}

async fn simulator_gosched() {
    for _ in 0..3 {
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_micros(50));
    }
}

fn f64_from_usize(value: usize) -> f64 {
    f64::from(u32::try_from(value).expect("test matrix count fits u32"))
}

fn f64_from_i64(value: i64) -> f64 {
    f64::from(i32::try_from(value).expect("test round fits i32"))
}

fn all_started_peers_decided(results: &[SimResult], config: &SimConfig) -> bool {
    results.iter().all(|result| {
        result.decided
            || config
                .start_by_peer
                .get(&result.peer_idx)
                .is_some_and(|delay| *delay == DISABLED)
    })
}

struct SimNetwork {
    nodes: Arc<Mutex<Vec<Arc<Consensus>>>>,
    pending: Arc<Mutex<Vec<PendingDelivery>>>,
}

struct PendingDelivery {
    peer_idx: usize,
    deliver_at: Instant,
    msg: pbconsensus::QbftConsensusMsg,
}

impl SimNetwork {
    fn new(
        peer_count: usize,
        config: &SimConfig,
        round_tx: mpsc::UnboundedSender<(usize, i64)>,
    ) -> Self {
        let nodes = Arc::new(Mutex::new(Vec::with_capacity(peer_count)));
        let pending = Arc::new(Mutex::new(Vec::new()));
        let peers = peers(peer_count);
        let rng = Arc::new(Mutex::new(TestRng::new(config.seed)));
        let latency_per_peer = Arc::new(config.latency_per_peer.clone());

        for peer_idx in 0..peer_count {
            let pending = Arc::clone(&pending);
            let rng = Arc::clone(&rng);
            let latency_per_peer = Arc::clone(&latency_per_peer);
            let latency_jitter = config.latency_jitter;
            let broadcaster: component::Broadcaster = Arc::new(move |ct, msg| {
                let pending = Arc::clone(&pending);
                let rng = Arc::clone(&rng);
                let latency_per_peer = Arc::clone(&latency_per_peer);
                Box::pin(async move {
                    broadcast_with_latency(pending, rng, latency_per_peer, latency_jitter, ct, msg)
                        .await
                })
            });

            let consensus = Arc::new(
                Consensus::new(Config {
                    peers: peers.clone(),
                    local_peer_idx: i64::try_from(peer_idx).expect("test peer index fits i64"),
                    privkey: component::tests::secret_key(
                        u8::try_from(peer_idx.checked_add(1).expect("test peer index increments"))
                            .expect("test peer index fits u8"),
                    ),
                    broadcaster,
                    timer_func: timer_func(config.timer_strategy),
                    sniffer: {
                        let round_tx = round_tx.clone();
                        Arc::new(move |instance| {
                            if let Some(round) = decided_round_from_sniffer(&instance) {
                                let _ = round_tx.send((peer_idx, round));
                            }
                        })
                    },
                    ..component::tests::config_base(false)
                })
                .unwrap(),
            );
            nodes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(consensus);
        }

        Self { nodes, pending }
    }

    fn nodes(&self) -> Vec<Arc<Consensus>> {
        self.nodes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn cancel(&self) {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    async fn process_buffer(&self) {
        loop {
            let now = Instant::now();
            let mut due = {
                let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
                let mut due = Vec::new();
                let mut index = 0;
                while index < pending.len() {
                    if pending[index].deliver_at <= now {
                        due.push(pending.swap_remove(index));
                    } else {
                        index = index.checked_add(1).expect("pending index increments");
                    }
                }
                due
            };

            if due.is_empty() {
                return;
            }

            due.sort_by_key(|delivery| (delivery.deliver_at, delivery.peer_idx));
            let nodes = self.nodes();
            for delivery in due {
                if let Some(node) = nodes.get(delivery.peer_idx) {
                    let delivery_ct = CancellationToken::new();
                    let _ = node.handle(delivery.msg, &delivery_ct).await;
                }
            }
        }
    }
}

fn decided_round_from_sniffer(instance: &pbconsensus::SniffedConsensusInstance) -> Option<i64> {
    instance
        .msgs
        .iter()
        .filter_map(|sniffed| sniffed.msg.as_ref())
        .filter_map(|outer| outer.msg.as_ref())
        .filter(|msg| msg.r#type == i64::from(qbft::MSG_COMMIT))
        .map(|msg| msg.round)
        .max()
}

async fn broadcast_with_latency(
    pending: Arc<Mutex<Vec<PendingDelivery>>>,
    rng: Arc<Mutex<TestRng>>,
    latency_per_peer: Arc<BTreeMap<usize, Duration>>,
    latency_jitter: Duration,
    sender_ct: CancellationToken,
    msg: pbconsensus::QbftConsensusMsg,
) -> component::BroadcastResult {
    if sender_ct.is_cancelled() {
        return Ok(());
    }

    let source = msg.msg.as_ref().map_or(-1, |msg| msg.peer_idx);
    let mut pending = pending.lock().unwrap_or_else(PoisonError::into_inner);
    for peer_idx in latency_per_peer.keys().copied() {
        if i64::try_from(peer_idx).expect("test peer index fits i64") == source {
            continue;
        }

        let Some(mean) = latency_per_peer.get(&peer_idx).copied() else {
            continue;
        };
        let delay = {
            let mut rng = rng.lock().unwrap_or_else(PoisonError::into_inner);
            jittered_latency(mean, latency_jitter, &mut rng)
        };
        let deliver_at = Instant::now()
            .checked_add(delay)
            .expect("test delivery deadline fits Instant");
        pending.push(PendingDelivery {
            peer_idx,
            deliver_at,
            msg: msg.clone(),
        });
    }

    Ok(())
}

fn timer_func(strategy: TimerStrategy) -> RoundTimerFunc {
    Box::new(move |_| Box::new(StrategyRoundTimer::new(strategy)))
}

#[derive(Debug)]
struct StrategyRoundTimer {
    strategy: TimerStrategy,
    deadlines: Mutex<HashMap<i64, Instant>>,
}

impl StrategyRoundTimer {
    fn new(strategy: TimerStrategy) -> Self {
        Self {
            strategy,
            deadlines: Mutex::new(HashMap::new()),
        }
    }
}

impl RoundTimer for StrategyRoundTimer {
    fn timer_type(&self) -> TimerType {
        self.strategy.timer_type()
    }

    fn timer(&self, round: i64) -> crate::timer::Result<RoundTimerFuture> {
        let duration = self.strategy.duration(round);
        let mut deadlines = self
            .deadlines
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let deadline = match deadlines.entry(round) {
            Entry::Occupied(mut entry) if self.strategy.double() => {
                let deadline = entry
                    .get()
                    .checked_add(duration)
                    .expect("test timer deadline fits");
                entry.insert(deadline);
                deadline
            }
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let deadline = Instant::now()
                    .checked_add(duration)
                    .expect("test timer deadline fits");
                entry.insert(deadline);
                deadline
            }
        };

        Ok(Box::pin(async move {
            tokio::time::sleep_until(deadline).await;
            deadline
        }))
    }
}

fn matrix_configs(iters_per_config: usize) -> Vec<SimConfig> {
    let sizes = [
        ("small-all", 4usize, 4usize),
        ("small-min", 3, 4),
        ("medium-all", 6, 6),
        ("medium-min", 4, 6),
        ("large-all", 9, 9),
        ("large-min", 6, 9),
    ];
    let distributions = [
        (
            "colocated",
            vec![Duration::from_millis(5), Duration::from_millis(10)],
            vec![
                Duration::from_millis(5),
                Duration::from_millis(10),
                Duration::from_millis(25),
                Duration::from_millis(50),
            ],
        ),
        (
            "regional",
            vec![Duration::from_millis(10), Duration::from_millis(25)],
            vec![
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_millis(250),
            ],
        ),
        (
            "global",
            vec![Duration::from_millis(50), Duration::from_millis(100)],
            vec![
                Duration::from_millis(250),
                Duration::from_millis(250),
                Duration::from_millis(500),
                Duration::from_millis(500),
                Duration::from_millis(750),
            ],
        ),
    ];
    let timers = [
        TimerStrategy::Increasing,
        TimerStrategy::Exp {
            base: Duration::from_millis(1_000),
        },
        TimerStrategy::ExpDouble {
            base: Duration::from_millis(1_000),
        },
        TimerStrategy::Linear {
            base: Duration::from_millis(1_000),
        },
        TimerStrategy::LinearDouble {
            base: Duration::from_millis(1_000),
        },
    ];

    let mut configs = Vec::new();
    for (size, up, nodes) in sizes {
        for (distribution, jitters, latencies) in &distributions {
            for timer_strategy in timers {
                let disabled_count = nodes.checked_sub(up).expect("up count is bounded by nodes");
                let mut timer_configs = random_configs(
                    MatrixLabel { size, distribution },
                    nodes,
                    iters_per_config,
                    timer_strategy,
                    jitters,
                    latencies,
                );
                disable_random_nodes(&mut timer_configs, disabled_count);
                configs.extend(timer_configs);
            }
        }
    }

    configs
}

fn print_matrix_summaries(summaries: &BTreeMap<MatrixKey, MatrixSummary>) {
    print_summary_header();
    for (key, summary) in summaries {
        print_summary(key.size, key.distribution, &key.timer, summary);
    }
}

fn print_timer_aggregates(summaries: &BTreeMap<MatrixKey, MatrixSummary>) {
    println!("\n\nTimer aggregate results\n");

    let mut aggregates = BTreeMap::<String, MatrixSummary>::new();
    for (key, summary) in summaries {
        let aggregate = aggregates.entry(key.timer.clone()).or_default();
        aggregate.total = aggregate
            .total
            .checked_add(summary.total)
            .expect("aggregate total fits usize");
        aggregate.undecided = aggregate
            .undecided
            .checked_add(summary.undecided)
            .expect("aggregate undecided count fits usize");
        aggregate.rounds.extend(summary.rounds.iter().copied());
        aggregate
            .durations
            .extend(summary.durations.iter().copied());
    }

    print_summary_header();
    for (timer, summary) in aggregates {
        print_summary("", "", &timer, &summary);
    }
}

fn print_summary_header() {
    println!("Size\tDistribution\tTimer\tTotal\tUndecided\tAvgRound\tMeanDuration\tStdDevDuration");
}

fn print_summary(size: &str, distribution: &str, timer: &str, summary: &MatrixSummary) {
    println!(
        "{size}\t{distribution}\t{timer}\t{}\t{:.2}%\t{:.2}\t{:.2}s\t{:.2}s",
        summary.total,
        summary.undecided_percent(),
        summary.avg_round(),
        summary.avg_duration().as_secs_f64(),
        summary.stddev_duration().as_secs_f64()
    );
}

fn random_configs(
    label: MatrixLabel,
    peer_count: usize,
    count: usize,
    timer_strategy: TimerStrategy,
    jitters: &[Duration],
    latencies: &[Duration],
) -> Vec<SimConfig> {
    let mut rng = TestRng::new(0);
    let mut configs = Vec::with_capacity(count);

    for seed in 0..count {
        let mut latency_per_peer = BTreeMap::new();
        for peer_idx in 0..peer_count {
            latency_per_peer.insert(peer_idx, latencies[rng.gen_range(latencies.len())]);
        }

        configs.push(SimConfig {
            label: Some(label),
            seed: u64::try_from(seed).expect("test seed fits u64"),
            latency_jitter: jitters[seed.checked_rem(jitters.len()).expect("non-empty jitters")],
            latency_per_peer,
            start_by_peer: jittered_start_latencies(peer_count, &mut rng),
            timer_strategy,
            timeout: SIM_TIMEOUT,
        });
    }

    configs
}

fn disable_random_nodes(configs: &mut [SimConfig], count: usize) {
    let mut rng = TestRng::new(0);

    for config in configs {
        let peer_count = config.latency_per_peer.len();
        assert!(count <= peer_count);

        let mut disabled = HashSet::with_capacity(count);
        while disabled.len() < count {
            disabled.insert(rng.gen_range(peer_count));
        }

        for peer_idx in disabled {
            config.start_by_peer.insert(peer_idx, DISABLED);
        }
    }
}

fn jittered_start_latencies(peer_count: usize, rng: &mut TestRng) -> BTreeMap<usize, Duration> {
    let mut starts = BTreeMap::new();
    for peer_idx in 0..peer_count {
        starts.insert(
            peer_idx,
            jittered_latency(Duration::from_millis(463), Duration::from_millis(273), rng),
        );
    }

    starts
}

fn jittered_latency(mean: Duration, jitter: Duration, rng: &mut TestRng) -> Duration {
    if jitter.is_zero() {
        return mean;
    }

    let spread = u64::try_from(jitter.as_nanos()).expect("test jitter fits u64 nanos");
    let range = spread
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .expect("test jitter range fits u64");
    let sample = rng
        .next_u64()
        .checked_rem(range)
        .expect("test jitter range is non-zero");

    if sample <= spread {
        mean.checked_sub(Duration::from_nanos(
            spread
                .checked_sub(sample)
                .expect("sample is bounded by spread"),
        ))
        .unwrap_or(Duration::ZERO)
    } else {
        mean.checked_add(Duration::from_nanos(
            sample
                .checked_sub(spread)
                .expect("sample is greater than spread"),
        ))
        .expect("test jittered latency fits Duration")
    }
}

struct TestRng {
    state: u64,
}

impl TestRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.state
    }

    fn gen_range(&mut self, end: usize) -> usize {
        let end = u64::try_from(end).expect("test range fits u64");
        assert_ne!(end, 0);
        usize::try_from(
            self.next_u64()
                .checked_rem(end)
                .expect("test range is non-zero"),
        )
        .expect("test sample fits usize")
    }
}

fn peers(count: usize) -> Vec<Peer> {
    (0..count)
        .map(|index| Peer {
            index: i64::try_from(index).expect("test peer index fits i64"),
            name: format!("node-{index}"),
            public_key: component::tests::secret_key(
                u8::try_from(index.checked_add(1).expect("test peer index increments"))
                    .expect("test peer index fits u8"),
            )
            .public_key(),
        })
        .collect()
}

fn unsigned_value(seed: usize) -> pbcore::UnsignedDataSet {
    let mut set = BTreeMap::new();
    set.insert(
        format!("validator-{seed}"),
        Bytes::from(format!("unsigned-{seed}")),
    );
    pbcore::UnsignedDataSet { set }
}
