//! Dial-campaign machinery: backoff scheduling and the per-target dial state.
//!
//! A [`RelayDialState`] is a [`Stream`] that yields a `ToSwarm::Dial` each time
//! its exponential backoff elapses, so the swarm re-dials a relay (or a routed
//! cluster peer) until it connects.

use std::{
    collections::HashSet,
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::Stream;
use libp2p::{
    Multiaddr, PeerId,
    swarm::{ToSwarm, dial_opts::DialOpts},
};
use tokio::time::{Instant, Sleep, sleep_until};

use super::event::{RelayDialType, RelayManagerEvent};

/// Initial backoff delay before the first reconnect attempt. Matches Charon's
/// `DefaultConfig.BaseDelay`.
const RELAY_BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Maximum backoff delay between reconnect attempts. Matches Charon's
/// `DefaultConfig.MaxDelay`.
const RELAY_BACKOFF_MAX: Duration = Duration::from_secs(120);
/// Jitter factor applied to backoff delays. Matches Charon's
/// `DefaultConfig.Jitter`.
const RELAY_BACKOFF_JITTER: f64 = 0.2;

/// State of an in-flight dial campaign, polled to produce a `ToSwarm::Dial`
/// event each time its backoff elapses.
pub(super) struct RelayDialState {
    /// Kind of target this campaign is dialing.
    pub(super) ty: RelayDialType,
    /// Target peer id for the dial.
    pub(super) peer_id: PeerId,
    /// Transport (for `RelayServer`) or circuit (for `ClusterPeer`) addresses
    /// to try.
    pub(super) addrs: Vec<Multiaddr>,
    /// Number of dial attempts so far, used to compute the next backoff.
    pub(super) retry_count: u32,
    /// Sleeps until the next dial is due. Boxed-and-pinned so the struct stays
    /// `Unpin` and can be stored in a `HashMap`; the inner `Sleep` is `!Unpin`.
    sleep: Pin<Box<Sleep>>,
}

impl RelayDialState {
    /// Creates a fresh dial state armed to fire after the base backoff.
    pub(super) fn new(ty: RelayDialType, peer_id: PeerId, addrs: Vec<Multiaddr>) -> Self {
        Self {
            ty,
            peer_id,
            addrs,
            retry_count: 0,
            sleep: Box::pin(sleep_until(Instant::now())),
        }
    }
}

impl Stream for RelayDialState {
    type Item = ToSwarm<RelayManagerEvent, Infallible>;

    /// Drives the dial schedule. Yields a `Dial` event when the next attempt
    /// is due, then self-rearms with an exponential backoff so subsequent
    /// `poll_next` calls produce later retries. The stream never terminates.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        std::task::ready!(self.sleep.as_mut().poll(cx));

        let next_delay = backoff_delay(self.retry_count);
        self.retry_count = self.retry_count.saturating_add(1);
        let next_deadline = Instant::now()
            .checked_add(next_delay)
            .unwrap_or_else(Instant::now);
        self.sleep.as_mut().reset(next_deadline);

        let opts = DialOpts::peer_id(self.peer_id)
            .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
            .addresses(self.addrs.clone())
            .build();

        Poll::Ready(Some(ToSwarm::Dial { opts }))
    }
}

/// Returns true if both slices contain the same multiaddrs (order-independent).
/// Used to decide whether a routing refresh actually expanded the available
/// circuit paths to a peer — if it did, the dial state's backoff is reset.
pub(super) fn addr_sets_equal(a: &[Multiaddr], b: &[Multiaddr]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let a_set: HashSet<&Multiaddr> = a.iter().collect();
    let b_set: HashSet<&Multiaddr> = b.iter().collect();

    a_set == b_set
}

/// Exponential backoff delay for a given retry count.
///
/// Mirrors Charon's `expbackoff.DefaultConfig`: base=1s, multiplier=1.6,
/// jitter=0.2, max=120s. `retry_count == 0` returns the base delay with no
/// jitter, matching Go's early-return path. For `retry_count > 0`, ±20%
/// jitter is applied after capping so nodes don't retry in lockstep.
fn backoff_delay(retry_count: u32) -> Duration {
    if retry_count == 0 {
        return RELAY_BACKOFF_BASE;
    }
    let mut delay = RELAY_BACKOFF_BASE.as_secs_f64();
    let max = RELAY_BACKOFF_MAX.as_secs_f64();
    for _ in 0..retry_count {
        delay *= 1.6;
        if delay >= max {
            delay = max;
            break;
        }
    }
    let rand_val = rand::random::<f64>();
    delay *= 1.0 + RELAY_BACKOFF_JITTER * (rand_val * 2.0 - 1.0);
    if delay < 0.0 {
        return Duration::ZERO;
    }
    Duration::from_secs_f64(delay)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_delay_retry_zero_returns_base_exactly() {
        // Charon's early-return path: retry == 0 returns base with no jitter.
        assert_eq!(backoff_delay(0), RELAY_BACKOFF_BASE);
    }

    #[test]
    fn backoff_delay_caps_at_max_with_jitter_bound() {
        // 1.6^n grows past max well before retry == 50; we should be capped at
        // max ± 20% jitter and never wander outside that envelope.
        let max = RELAY_BACKOFF_MAX.as_secs_f64();
        let lower = max * (1.0 - RELAY_BACKOFF_JITTER);
        let upper = max * (1.0 + RELAY_BACKOFF_JITTER);
        for _ in 0..32 {
            let d = backoff_delay(50).as_secs_f64();
            assert!(
                d >= lower && d <= upper,
                "delay {d}s outside jitter envelope [{lower}, {upper}]"
            );
        }
    }

    #[test]
    fn backoff_delay_grows_then_plateaus() {
        // Averaging out jitter, retry=1 should be larger than base and
        // retry=10 should already be at the cap.
        let mut sum_1 = 0.0;
        let mut sum_10 = 0.0;
        let samples = 64;
        for _ in 0..samples {
            sum_1 += backoff_delay(1).as_secs_f64();
            sum_10 += backoff_delay(10).as_secs_f64();
        }
        let avg_1 = sum_1 / f64::from(samples);
        let avg_10 = sum_10 / f64::from(samples);
        assert!(avg_1 > RELAY_BACKOFF_BASE.as_secs_f64());
        assert!(avg_10 >= RELAY_BACKOFF_MAX.as_secs_f64() * (1.0 - RELAY_BACKOFF_JITTER));
    }
}
