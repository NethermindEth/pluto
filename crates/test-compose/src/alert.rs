//! Prometheus alert collection for the automated flow.
//!
//! While the cluster runs, the collector polls the Prometheus rules API
//! through the compose `curl` container and reports every alert that starts
//! firing. Rules known to fire on any healthy cluster while it boots are
//! ignored during a warmup window after Prometheus first answers.

use std::{
    collections::HashSet,
    future::Future,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;
use tokio::{
    process::Command,
    sync::mpsc,
    time::{self, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    define::{BROADCAST_RULE, ERROR_RATE_RULE, WARN_RATE_RULE, combined_output},
    duration::go_duration_string,
    error::{CommandError, ComposeError, Result},
};

/// Sentinel sent on the alert channel when polling was still healthy at the
/// end of the observation window.
pub const ALERTS_POLLED: &str = "alerts_polled";

/// Window after Prometheus first answers during which the cold-start
/// transients are ignored.
pub const ALERT_WARMUP: Duration = Duration::from_secs(60);

/// Interval between two polls of the rules API.
pub const ALERT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Alert rules that fire on any healthy cluster while it boots: log rates and
/// broadcast latency spike while the nodes find each other and sync.
pub const STARTUP_TRANSIENT_RULES: [&str; 3] = [ERROR_RATE_RULE, WARN_RATE_RULE, BROADCAST_RULE];

/// Returns whether `rule` may fire during warmup without being reported.
pub fn is_startup_transient(rule: impl AsRef<str>) -> bool {
    STARTUP_TRANSIENT_RULES.contains(&rule.as_ref())
}

/// Cadence of the alert collector. The defaults are what the harness runs
/// with; the knob exists so docker-free tests can finish quickly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertTiming {
    /// Time after Prometheus first answers during which startup transients
    /// are ignored.
    pub warmup: Duration,
    /// Time between two polls.
    pub poll_interval: Duration,
}

impl Default for AlertTiming {
    fn default() -> Self {
        Self {
            warmup: ALERT_WARMUP,
            poll_interval: ALERT_POLL_INTERVAL,
        }
    }
}

/// A firing alert: the rule name and its rendered description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveAlert {
    /// The alert rule name.
    pub rule: String,
    /// The rendered `description` annotation.
    pub description: String,
}

/// Response of `GET /api/v1/rules?type=alert`. Unknown fields are ignored and
/// missing ones default, as with Go's `encoding/json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PromAlerts {
    /// `"success"` on a healthy response.
    #[serde(default)]
    pub status: String,
    /// The rule groups.
    #[serde(default)]
    pub data: PromData,
}

/// The `data` object of a rules API response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PromData {
    /// The rule groups.
    #[serde(default)]
    pub groups: Vec<PromGroup>,
}

/// A rule group.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PromGroup {
    /// The group name.
    #[serde(default)]
    pub name: String,
    /// The alerting rules in the group.
    #[serde(default)]
    pub rules: Vec<PromRule>,
}

/// An alerting rule with its current alerts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PromRule {
    /// The rule name.
    #[serde(default)]
    pub name: String,
    /// The alerts the rule currently produces.
    #[serde(default)]
    pub alerts: Vec<PromAlert>,
}

/// One alert instance of a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PromAlert {
    /// `firing`, `pending` or `inactive`.
    #[serde(default)]
    pub state: String,
    /// The alert annotations.
    #[serde(default)]
    pub annotations: PromAnnotations,
}

/// The annotations of an alert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PromAlertAnnotations {
    /// The rendered description.
    #[serde(default)]
    pub description: String,
}

/// Annotations of an alert instance.
pub type PromAnnotations = PromAlertAnnotations;

/// Source of alert rule snapshots.
pub trait AlertPoller: Send + Sync + 'static {
    /// Fetches the current alerting rules.
    fn query(&self) -> impl Future<Output = Result<PromAlerts>> + Send;
}

/// Polls Prometheus through the compose `curl` container.
#[derive(Debug, Clone)]
pub struct DockerCurlPoller {
    dir: PathBuf,
}

impl DockerCurlPoller {
    /// A poller for the cluster in compose directory `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

impl AlertPoller for DockerCurlPoller {
    async fn query(&self) -> Result<PromAlerts> {
        query_alerts(&self.dir).await
    }
}

/// Runs `docker compose exec -T curl curl -s <rules API>` in `dir` and parses
/// the response.
async fn query_alerts(dir: &Path) -> Result<PromAlerts> {
    let output = Command::new("docker")
        .args([
            "compose",
            "exec",
            "-T",
            "curl",
            "curl",
            "-s",
            "http://prometheus:9090/api/v1/rules?type=alert",
        ])
        .current_dir(dir)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|err| ComposeError::ExecCurlAlerts {
            source: CommandError::Io(err),
            out: String::new(),
        })?;

    let out = combined_output(&output);
    if !output.status.success() {
        return Err(ComposeError::ExecCurlAlerts {
            source: CommandError::Exit(output.status),
            out,
        });
    }

    serde_json::from_str(out.trim()).map_err(|source| ComposeError::UnmarshalAlerts { source, out })
}

/// Starts polling alerts on a background task until `token` is cancelled.
///
/// Every newly firing alert description is sent on the returned channel. When
/// the token fires, the collector sends [`ALERTS_POLLED`] as its last message
/// if the final poll succeeded and at least one poll succeeded after the
/// warmup window, then closes the channel.
pub fn start_collector(
    token: CancellationToken,
    poller: impl AlertPoller,
    timing: AlertTiming,
) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel(100);
    tokio::spawn(collect(token, poller, timing, tx));
    rx
}

async fn collect(
    token: CancellationToken,
    poller: impl AlertPoller,
    timing: AlertTiming,
    tx: mpsc::Sender<String>,
) {
    let Some(ready_at) = await_prometheus_ready(&token, &poller, timing.poll_interval).await else {
        return;
    };

    info!(
        warmup = %go_duration_string(timing.warmup),
        "Prometheus ready, collecting alerts"
    );

    // `None` only on Instant overflow, in which case warmup never ends.
    let warmup_end = ready_at.checked_add(timing.warmup);
    let mut reported = HashSet::new();
    let mut ignored = HashSet::new();
    let mut last_poll_ok = false;
    let mut post_warmup_poll_ok = false;

    while !token.is_cancelled() {
        let Some(result) = query_or_cancel(&token, &poller).await else {
            break;
        };

        match result {
            Err(err) => {
                last_poll_ok = false;
                error!(%err, "Poll prometheus alerts");
            }
            Ok(alerts) if alerts.status != "success" => {
                last_poll_ok = false;
                let _ = tx
                    .send(format!(
                        "non success status from prometheus alerts: {}",
                        alerts.status
                    ))
                    .await;
            }
            Ok(alerts) => {
                last_poll_ok = true;

                let in_warmup = warmup_end.is_none_or(|end| Instant::now() < end);
                if !in_warmup {
                    post_warmup_poll_ok = true;
                }

                for active in get_active_alerts(&alerts) {
                    if in_warmup && is_startup_transient(&active.rule) {
                        if ignored.insert(active.description.clone()) {
                            info!(
                                alert = %active.description,
                                "Ignoring known cold-start transient during warmup"
                            );
                        }

                        continue;
                    }

                    if !reported.insert(active.description.clone()) {
                        continue;
                    }

                    info!(alert = %active.description, "Detected new alert");

                    let _ = tx.send(active.description).await;
                }
            }
        }

        sleep_or_cancel(&token, timing.poll_interval).await;
    }

    if post_warmup_poll_ok && last_poll_ok {
        let _ = tx.send(ALERTS_POLLED.to_string()).await;
    }
}

/// Polls until the rules API answers with a success status and returns when
/// it did, or `None` when the token fired first.
async fn await_prometheus_ready(
    token: &CancellationToken,
    poller: &impl AlertPoller,
    poll_interval: Duration,
) -> Option<Instant> {
    info!("Waiting for prometheus to answer the rules API");

    while !token.is_cancelled() {
        if let Some(Ok(alerts)) = query_or_cancel(token, poller).await
            && alerts.status == "success"
        {
            return Some(Instant::now());
        }

        sleep_or_cancel(token, poll_interval).await;
    }

    None
}

/// Runs one poll unless the token fires first.
///
/// Returns `None` when the window closed before or while the poll ran: that
/// failure is expected and must not count against the verdict. Abandoning the
/// query drops its future, which terminates the `docker compose exec` behind
/// it, so a stalled daemon cannot hold the collector (and with it the final
/// teardown) past the observation window.
async fn query_or_cancel(
    token: &CancellationToken,
    poller: &impl AlertPoller,
) -> Option<Result<PromAlerts>> {
    let result = tokio::select! {
        result = poller.query() => result,
        () = token.cancelled() => return None,
    };

    (!token.is_cancelled()).then_some(result)
}

async fn sleep_or_cancel(token: &CancellationToken, duration: Duration) {
    tokio::select! {
        () = time::sleep(duration) => {}
        () = token.cancelled() => {}
    }
}

/// Extracts the firing alerts of a rules API response, in response order.
pub fn get_active_alerts(alerts: &PromAlerts) -> Vec<ActiveAlert> {
    let mut active = Vec::new();
    for group in &alerts.data.groups {
        for rule in &group.rules {
            for alert in &rule.alerts {
                if alert.state != "firing" {
                    continue;
                }

                active.push(ActiveAlert {
                    rule: rule.name.clone(),
                    description: alert.annotations.description.clone(),
                });
            }
        }
    }

    active
}

#[cfg(test)]
mod tests {
    use std::io;

    use test_case::test_case;

    use super::*;
    use crate::define::{PLUTO_DOWN_RULE, PROXY_RATE_RULE, VAPI_RATE_RULE};

    #[test]
    fn get_active_alerts_firing_only() {
        let payload = r#"{
            "status": "success",
            "data": {
                "groups": [{
                    "name": "cluster",
                    "rules": [
                        {
                            "name": "Error Log Rate",
                            "alerts": [
                                {"state": "firing", "annotations": {"description": "node0 has a high error rate"}},
                                {"state": "pending", "annotations": {"description": "node1 has a high error rate"}}
                            ]
                        },
                        {
                            "name": "Pluto Down",
                            "alerts": [
                                {"state": "inactive", "annotations": {"description": "node2 is down"}},
                                {"state": "active", "annotations": {"description": "node3 is down"}}
                            ]
                        }
                    ]
                }]
            }
        }"#;
        let alerts: PromAlerts = serde_json::from_str(payload).expect("parse payload");

        let active = get_active_alerts(&alerts);

        assert_eq!(
            active,
            vec![ActiveAlert {
                rule: "Error Log Rate".to_string(),
                description: "node0 has a high error rate".to_string(),
            }]
        );
    }

    #[test]
    fn startup_transient_rules_scoped() {
        assert!(is_startup_transient(ERROR_RATE_RULE));
        assert!(is_startup_transient(WARN_RATE_RULE));
        assert!(is_startup_transient(BROADCAST_RULE));
        assert!(!is_startup_transient(PLUTO_DOWN_RULE));
        assert!(!is_startup_transient(VAPI_RATE_RULE));
        assert!(!is_startup_transient(PROXY_RATE_RULE));
        assert_eq!(STARTUP_TRANSIENT_RULES.len(), 3);
    }

    #[test]
    fn prom_alerts_tolerates_missing_and_unknown_fields() {
        let alerts: PromAlerts = serde_json::from_str(
            r#"{"status":"success","extra":1,"data":{"groups":[{"rules":[{"alerts":[{}]}]}]}}"#,
        )
        .expect("parse payload");

        assert_eq!(alerts.status, "success");
        assert_eq!(alerts.data.groups.len(), 1);
        assert!(get_active_alerts(&alerts).is_empty());
    }

    #[test]
    fn alert_timing_default_matches_harness() {
        assert_eq!(
            AlertTiming::default(),
            AlertTiming {
                warmup: Duration::from_secs(60),
                poll_interval: Duration::from_secs(2),
            }
        );
    }

    /// Answers each poll from a script keyed by the time elapsed since the
    /// poller was created.
    struct ScriptedPoller {
        start: Instant,
        script: Box<dyn Fn(Duration) -> Result<PromAlerts> + Send + Sync>,
    }

    impl AlertPoller for ScriptedPoller {
        async fn query(&self) -> Result<PromAlerts> {
            (self.script)(self.start.elapsed())
        }
    }

    fn healthy() -> Result<PromAlerts> {
        Ok(PromAlerts {
            status: "success".to_string(),
            data: PromData::default(),
        })
    }

    fn with_status(status: &str) -> Result<PromAlerts> {
        Ok(PromAlerts {
            status: status.to_string(),
            data: PromData::default(),
        })
    }

    fn firing(rule: &str, description: &str) -> Result<PromAlerts> {
        Ok(PromAlerts {
            status: "success".to_string(),
            data: PromData {
                groups: vec![PromGroup {
                    name: "cluster".to_string(),
                    rules: vec![PromRule {
                        name: rule.to_string(),
                        alerts: vec![PromAlert {
                            state: "firing".to_string(),
                            annotations: PromAlertAnnotations {
                                description: description.to_string(),
                            },
                        }],
                    }],
                }],
            },
        })
    }

    fn failing() -> Result<PromAlerts> {
        Err(ComposeError::ExecCurlAlerts {
            source: CommandError::Io(io::Error::other("no such container")),
            out: String::new(),
        })
    }

    /// Runs the collector with the harness cadence under paused time for
    /// `window` (an odd number of seconds, so the deadline never coincides
    /// with a poll), then cancels it and drains the channel.
    async fn run_collector(
        window: Duration,
        script: impl Fn(Duration) -> Result<PromAlerts> + Send + Sync + 'static,
    ) -> Vec<String> {
        let token = CancellationToken::new();
        let poller = ScriptedPoller {
            start: Instant::now(),
            script: Box::new(script),
        };
        let mut rx = start_collector(token.clone(), poller, AlertTiming::default());

        time::sleep(window).await;
        token.cancel();

        let mut messages = Vec::new();
        while let Some(message) = rx.recv().await {
            messages.push(message);
        }

        messages
    }

    const WINDOW: Duration = Duration::from_secs(125);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_window_reports_polled_only() {
        let messages = run_collector(WINDOW, |_| healthy()).await;
        assert_eq!(messages, vec![ALERTS_POLLED.to_string()]);
    }

    #[tokio::test(start_paused = true)]
    async fn poller_dying_after_warmup_withholds_polled() {
        let messages =
            run_collector(WINDOW, |t| if t < secs(70) { healthy() } else { failing() }).await;
        assert!(messages.is_empty(), "{messages:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn poller_recovering_before_deadline_reports_polled() {
        let messages = run_collector(WINDOW, |t| {
            if (secs(70)..secs(90)).contains(&t) {
                failing()
            } else {
                healthy()
            }
        })
        .await;
        assert_eq!(messages, vec![ALERTS_POLLED.to_string()]);
    }

    #[tokio::test(start_paused = true)]
    async fn never_ready_reports_nothing() {
        let messages = run_collector(WINDOW, |_| failing()).await;
        assert!(messages.is_empty(), "{messages:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_waits_for_success_status() {
        let messages = run_collector(WINDOW, |t| {
            if t < secs(5) {
                with_status("error")
            } else {
                healthy()
            }
        })
        .await;
        assert_eq!(messages, vec![ALERTS_POLLED.to_string()]);
    }

    #[tokio::test(start_paused = true)]
    async fn non_success_status_is_reported_every_poll_and_withholds_polled() {
        let messages = run_collector(WINDOW, |t| {
            if t < secs(10) {
                healthy()
            } else {
                with_status("error")
            }
        })
        .await;
        assert!(!messages.is_empty());
        assert!(
            messages
                .iter()
                .all(|m| m == "non success status from prometheus alerts: error"),
            "{messages:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn non_transient_alert_during_warmup_is_reported() {
        let messages = run_collector(WINDOW, |t| {
            if (secs(10)..secs(14)).contains(&t) {
                firing(PLUTO_DOWN_RULE, "node0 is down")
            } else {
                healthy()
            }
        })
        .await;
        assert_eq!(
            messages,
            vec!["node0 is down".to_string(), ALERTS_POLLED.to_string()]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn transient_alert_only_during_warmup_is_ignored() {
        let messages = run_collector(WINDOW, |t| {
            if t < secs(30) {
                firing(ERROR_RATE_RULE, "node0 has a high error rate")
            } else {
                healthy()
            }
        })
        .await;
        assert_eq!(messages, vec![ALERTS_POLLED.to_string()]);
    }

    #[tokio::test(start_paused = true)]
    async fn transient_alert_outliving_warmup_is_reported_once() {
        let messages = run_collector(WINDOW, |t| {
            if t < secs(80) {
                firing(ERROR_RATE_RULE, "node0 has a high error rate")
            } else {
                healthy()
            }
        })
        .await;
        assert_eq!(
            messages,
            vec![
                "node0 has a high error rate".to_string(),
                ALERTS_POLLED.to_string()
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_alert_is_reported_once() {
        let messages = run_collector(WINDOW, |t| {
            if t >= secs(70) {
                firing(VAPI_RATE_RULE, "node1 has a high validator api error rate")
            } else {
                healthy()
            }
        })
        .await;
        assert_eq!(
            messages,
            vec![
                "node1 has a high validator api error rate".to_string(),
                ALERTS_POLLED.to_string()
            ]
        );
    }

    #[test_case(Duration::from_secs(60), "1m0s" ; "harness_default")]
    #[test_case(Duration::from_secs(1), "1s" ; "one_second")]
    fn warmup_is_logged_in_go_format(warmup: Duration, expected: &str) {
        assert_eq!(go_duration_string(warmup), expected);
    }

    /// Answers every poll with a healthy response until `stall_after` has
    /// elapsed since creation, then never answers again.
    struct StallingPoller {
        start: Instant,
        stall_after: Duration,
    }

    impl AlertPoller for StallingPoller {
        async fn query(&self) -> Result<PromAlerts> {
            if self.start.elapsed() < self.stall_after {
                return healthy();
            }

            std::future::pending().await
        }
    }

    /// Runs the collector against a poller that stalls after `stall_after`,
    /// cancels it after `window` and drains the channel, failing if the
    /// collector does not shut down promptly once cancelled.
    async fn run_stalling(window: Duration, stall_after: Duration) -> Vec<String> {
        let token = CancellationToken::new();
        let poller = StallingPoller {
            start: Instant::now(),
            stall_after,
        };
        let mut rx = start_collector(token.clone(), poller, AlertTiming::default());

        time::sleep(window).await;
        token.cancel();

        let drain = async {
            let mut messages = Vec::new();
            while let Some(message) = rx.recv().await {
                messages.push(message);
            }

            messages
        };

        time::timeout(secs(10), drain)
            .await
            .expect("collector did not stop after cancel")
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_readiness_query_stops_on_cancel() {
        let messages = run_stalling(WINDOW, Duration::ZERO).await;
        assert!(messages.is_empty(), "{messages:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_poll_during_warmup_stops_on_cancel_without_verdict() {
        let messages = run_stalling(WINDOW, secs(1)).await;
        assert!(messages.is_empty(), "{messages:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_poll_at_deadline_does_not_count_against_verdict() {
        let messages = run_stalling(WINDOW, secs(100)).await;
        assert_eq!(messages, vec![ALERTS_POLLED.to_string()]);
    }
}
