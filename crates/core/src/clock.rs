use chrono::{DateTime, Utc};

/// Provides the "current time".
///
/// [`ChronoClock`] is the production implementation; tests can supply a
/// deterministic clock instead. Any `Fn() -> DateTime<Utc>` also implements
/// this trait via the blanket impl below, so closures and [`chrono::Utc::now`]
/// can be used directly.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current time.
    fn now(&self) -> DateTime<Utc>;
}

/// [`Clock`] backed by the system wall clock via [`chrono::Utc::now`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ChronoClock;

impl Clock for ChronoClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

impl<F> Clock for F
where
    F: Fn() -> DateTime<Utc> + Send + Sync + 'static,
{
    fn now(&self) -> DateTime<Utc> {
        self()
    }
}
