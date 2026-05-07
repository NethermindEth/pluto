use super::{MessageType, Msg, QbftTypes, Result, UponRule};
use cancellation::CancellationToken;
use crossbeam::channel as mpmc;
use std::{marker::PhantomData, time};

pub trait Decider<T>: Send + Sync
where
    T: QbftTypes,
{
    fn decide(
        &self,
        ct: &CancellationToken,
        instance: &T::Instance,
        value: &T::Value,
        qcommit: &Vec<Msg<T>>,
    );
}

pub struct DeciderFn<T>
where
    T: QbftTypes,
{
    decide: Box<dyn Fn(&CancellationToken, &T::Instance, &T::Value, &Vec<Msg<T>>) + Send + Sync>,
    _marker: PhantomData<fn() -> T>,
}

impl<T> DeciderFn<T>
where
    T: QbftTypes,
{
    pub fn new<F>(decide: F) -> Self
    where
        F: Fn(&CancellationToken, &T::Instance, &T::Value, &Vec<Msg<T>>) + Send + Sync + 'static,
    {
        Self {
            decide: Box::new(decide),
            _marker: PhantomData,
        }
    }
}

impl<T> Decider<T> for DeciderFn<T>
where
    T: QbftTypes,
{
    fn decide(
        &self,
        ct: &CancellationToken,
        instance: &T::Instance,
        value: &T::Value,
        qcommit: &Vec<Msg<T>>,
    ) {
        (self.decide)(ct, instance, value, qcommit);
    }
}

pub trait LeaderSelector<T>: Send + Sync
where
    T: QbftTypes,
{
    fn is_leader(&self, instance: &T::Instance, round: i64, process: i64) -> bool;
}

pub struct LeaderSelectorFn<T>
where
    T: QbftTypes,
{
    is_leader: Box<dyn Fn(&T::Instance, i64, i64) -> bool + Send + Sync>,
    _marker: PhantomData<fn() -> T>,
}

impl<T> LeaderSelectorFn<T>
where
    T: QbftTypes,
{
    pub fn new<F>(is_leader: F) -> Self
    where
        F: Fn(&T::Instance, i64, i64) -> bool + Send + Sync + 'static,
    {
        Self {
            is_leader: Box::new(is_leader),
            _marker: PhantomData,
        }
    }
}

impl<T> LeaderSelector<T> for LeaderSelectorFn<T>
where
    T: QbftTypes,
{
    fn is_leader(&self, instance: &T::Instance, round: i64, process: i64) -> bool {
        (self.is_leader)(instance, round, process)
    }
}

pub trait QbftLogger<T>: Send + Sync
where
    T: QbftTypes,
{
    fn log_upon_rule(
        &self,
        instance: &T::Instance,
        process: i64,
        round: i64,
        msg: &Msg<T>,
        upon_rule: UponRule,
    );

    fn log_round_change(
        &self,
        instance: &T::Instance,
        process: i64,
        round: i64,
        new_round: i64,
        upon_rule: UponRule,
        msgs: &Vec<Msg<T>>,
    );

    fn log_unjust(&self, instance: &T::Instance, process: i64, msg: Msg<T>);
}

type LogUponRuleFn<T> =
    Box<dyn Fn(&<T as QbftTypes>::Instance, i64, i64, &Msg<T>, UponRule) + Send + Sync>;
type LogRoundChangeFn<T> =
    Box<dyn Fn(&<T as QbftTypes>::Instance, i64, i64, i64, UponRule, &Vec<Msg<T>>) + Send + Sync>;
type LogUnjustFn<T> = Box<dyn Fn(&<T as QbftTypes>::Instance, i64, Msg<T>) + Send + Sync>;

pub struct QbftLoggerFn<T>
where
    T: QbftTypes,
{
    log_upon_rule: LogUponRuleFn<T>,
    log_round_change: LogRoundChangeFn<T>,
    log_unjust: LogUnjustFn<T>,
    _marker: PhantomData<fn() -> T>,
}

impl<T> QbftLoggerFn<T>
where
    T: QbftTypes,
{
    pub fn new<F1, F2, F3>(log_upon_rule: F1, log_round_change: F2, log_unjust: F3) -> Self
    where
        F1: Fn(&T::Instance, i64, i64, &Msg<T>, UponRule) + Send + Sync + 'static,
        F2: Fn(&T::Instance, i64, i64, i64, UponRule, &Vec<Msg<T>>) + Send + Sync + 'static,
        F3: Fn(&T::Instance, i64, Msg<T>) + Send + Sync + 'static,
    {
        Self {
            log_upon_rule: Box::new(log_upon_rule),
            log_round_change: Box::new(log_round_change),
            log_unjust: Box::new(log_unjust),
            _marker: PhantomData,
        }
    }
}

impl<T> QbftLogger<T> for QbftLoggerFn<T>
where
    T: QbftTypes,
{
    fn log_upon_rule(
        &self,
        instance: &T::Instance,
        process: i64,
        round: i64,
        msg: &Msg<T>,
        upon_rule: UponRule,
    ) {
        (self.log_upon_rule)(instance, process, round, msg, upon_rule);
    }

    fn log_round_change(
        &self,
        instance: &T::Instance,
        process: i64,
        round: i64,
        new_round: i64,
        upon_rule: UponRule,
        msgs: &Vec<Msg<T>>,
    ) {
        (self.log_round_change)(instance, process, round, new_round, upon_rule, msgs);
    }

    fn log_unjust(&self, instance: &T::Instance, process: i64, msg: Msg<T>) {
        (self.log_unjust)(instance, process, msg);
    }
}

pub struct BroadcastRequest<'a, T>
where
    T: QbftTypes,
{
    pub ct: &'a CancellationToken,
    pub type_: MessageType,
    pub instance: &'a T::Instance,
    pub source: i64,
    pub round: i64,
    pub value: &'a T::Value,
    pub prepared_round: i64,
    pub prepared_value: &'a T::Value,
    pub justification: Option<&'a Vec<Msg<T>>>,
}

pub trait Broadcaster<T>: Send + Sync
where
    T: QbftTypes,
{
    fn broadcast(&self, request: BroadcastRequest<'_, T>) -> Result<()>;
}

type BroadcastFn<T> = Box<dyn Fn(BroadcastRequest<'_, T>) -> Result<()> + Send + Sync>;

pub struct BroadcasterFn<T>
where
    T: QbftTypes,
{
    broadcast: BroadcastFn<T>,
    _marker: PhantomData<fn() -> T>,
}

impl<T> BroadcasterFn<T>
where
    T: QbftTypes,
{
    pub fn new<F>(broadcast: F) -> Self
    where
        F: Fn(BroadcastRequest<'_, T>) -> Result<()> + Send + Sync + 'static,
    {
        Self {
            broadcast: Box::new(broadcast),
            _marker: PhantomData,
        }
    }
}

impl<T> Broadcaster<T> for BroadcasterFn<T>
where
    T: QbftTypes,
{
    fn broadcast(&self, request: BroadcastRequest<'_, T>) -> Result<()> {
        (self.broadcast)(request)
    }
}

pub trait TimerStopper: Send + Sync {
    fn stop(&self);
}

pub struct TimerStopperFn {
    stop: Box<dyn Fn() + Send + Sync>,
}

impl TimerStopperFn {
    pub fn new<F>(stop: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        Self {
            stop: Box::new(stop),
        }
    }
}

impl TimerStopper for TimerStopperFn {
    fn stop(&self) {
        (self.stop)();
    }
}

pub trait TimerFactory: Send + Sync {
    fn new_timer(&self, round: i64) -> (mpmc::Receiver<time::Instant>, Box<dyn TimerStopper>);
}

type NewTimerFn =
    Box<dyn Fn(i64) -> (mpmc::Receiver<time::Instant>, Box<dyn TimerStopper>) + Send + Sync>;

pub struct TimerFactoryFn {
    new_timer: NewTimerFn,
}

impl TimerFactoryFn {
    pub fn new<F>(new_timer: F) -> Self
    where
        F: Fn(i64) -> (mpmc::Receiver<time::Instant>, Box<dyn TimerStopper>)
            + Send
            + Sync
            + 'static,
    {
        Self {
            new_timer: Box::new(new_timer),
        }
    }
}

impl TimerFactory for TimerFactoryFn {
    fn new_timer(&self, round: i64) -> (mpmc::Receiver<time::Instant>, Box<dyn TimerStopper>) {
        (self.new_timer)(round)
    }
}

pub struct CompareRequest<'a, T>
where
    T: QbftTypes,
{
    pub ct: &'a CancellationToken,
    pub qcommit: &'a Msg<T>,
    pub input_value_source_ch: &'a mpmc::Receiver<T::Compare>,
    pub input_value_source: &'a T::Compare,
    pub return_err: &'a mpmc::Sender<Result<()>>,
    pub return_value: &'a mpmc::Sender<T::Compare>,
}

pub trait Comparator<T>: Send + Sync
where
    T: QbftTypes,
{
    fn compare(&self, request: CompareRequest<'_, T>);
}

pub struct ComparatorFn<T>
where
    T: QbftTypes,
{
    compare: Box<dyn Fn(CompareRequest<'_, T>) + Send + Sync>,
}

impl<T> ComparatorFn<T>
where
    T: QbftTypes,
{
    pub fn new<F>(compare: F) -> Self
    where
        F: Fn(CompareRequest<'_, T>) + Send + Sync + 'static,
    {
        Self {
            compare: Box::new(compare),
        }
    }
}

impl<T> Comparator<T> for ComparatorFn<T>
where
    T: QbftTypes,
{
    fn compare(&self, request: CompareRequest<'_, T>) {
        (self.compare)(request);
    }
}
