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
    define::{BROADCAST_RULE, ERROR_RATE_RULE, WARN_RATE_RULE},
    error::{CommandError, ComposeError, Result},
};

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

/// What the collector reports on its channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertEvent {
    /// A newly firing alert, or a non-success status from Prometheus.
    Alert(String),
    /// Sent last, only when polling was still healthy at the end of the
    /// observation window.
    Polled,
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
    pub annotations: PromAlertAnnotations,
}

/// The annotations of an alert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PromAlertAnnotations {
    /// The rendered description.
    #[serde(default)]
    pub description: String,
}

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
        .await;

    let output =
        CommandError::check_output(output).map_err(ComposeError::exec("exec curl alerts"))?;

    // curl -s puts the body on stdout; a plain-text error page it may have
    // fetched belongs in the message too.
    let out = crate::error::combined_output(&output);

    serde_json::from_str(out.trim()).map_err(|source| ComposeError::UnmarshalAlerts { source, out })
}

/// Starts polling alerts on a background task until `token` is cancelled.
///
/// Every newly firing alert description is sent on the returned channel. When
/// the token fires, the collector sends [`AlertEvent::Polled`] as its last
/// message if the final poll succeeded and at least one poll succeeded after
/// the warmup window, then closes the channel.
pub fn start_collector(
    token: CancellationToken,
    poller: impl AlertPoller,
) -> mpsc::Receiver<AlertEvent> {
    let (tx, rx) = mpsc::channel(100);
    tokio::spawn(collect(token, poller, tx));
    rx
}

async fn collect(token: CancellationToken, poller: impl AlertPoller, tx: mpsc::Sender<AlertEvent>) {
    let Some(ready_at) = await_prometheus_ready(&token, &poller).await else {
        return;
    };

    info!(
        warmup = ?ALERT_WARMUP,
        "Prometheus ready, collecting alerts"
    );

    // `None` only on Instant overflow, in which case warmup never ends.
    let warmup_end = ready_at.checked_add(ALERT_WARMUP);
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
                    .send(AlertEvent::Alert(format!(
                        "non success status from prometheus alerts: {}",
                        alerts.status
                    )))
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

                    let _ = tx.send(AlertEvent::Alert(active.description)).await;
                }
            }
        }

        sleep_or_cancel(&token, ALERT_POLL_INTERVAL).await;
    }

    if post_warmup_poll_ok && last_poll_ok {
        let _ = tx.send(AlertEvent::Polled).await;
    }
}

/// Polls until the rules API answers with a success status and returns when
/// it did, or `None` when the token fired first.
async fn await_prometheus_ready(
    token: &CancellationToken,
    poller: &impl AlertPoller,
) -> Option<Instant> {
    info!("Waiting for prometheus to answer the rules API");

    while !token.is_cancelled() {
        if let Some(Ok(alerts)) = query_or_cancel(token, poller).await
            && alerts.status == "success"
        {
            return Some(Instant::now());
        }

        sleep_or_cancel(token, ALERT_POLL_INTERVAL).await;
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
    let result = token.run_until_cancelled(poller.query()).await?;

    (!token.is_cancelled()).then_some(result)
}

async fn sleep_or_cancel(token: &CancellationToken, duration: Duration) {
    let _ = token.run_until_cancelled(time::sleep(duration)).await;
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
        Err(ComposeError::exec("exec curl alerts")(io::Error::other(
            "no such container",
        )))
    }

    /// Runs the collector with the harness cadence under paused time for
    /// `window` (an odd number of seconds, so the deadline never coincides
    /// with a poll), then cancels it and drains the channel.
    async fn run_collector(
        window: Duration,
        script: impl Fn(Duration) -> Result<PromAlerts> + Send + Sync + 'static,
    ) -> Vec<AlertEvent> {
        let token = CancellationToken::new();
        let poller = ScriptedPoller {
            start: Instant::now(),
            script: Box::new(script),
        };
        let mut rx = start_collector(token.clone(), poller);

        time::sleep(window).await;
        token.cancel();

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
        }

        events
    }

    const WINDOW: Duration = Duration::from_secs(125);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_window_reports_polled_only() {
        let events = run_collector(WINDOW, |_| healthy()).await;
        assert_eq!(events, vec![AlertEvent::Polled]);
    }

    #[tokio::test(start_paused = true)]
    async fn never_ready_reports_nothing() {
        let events = run_collector(WINDOW, |_| failing()).await;
        assert!(events.is_empty(), "{events:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn transient_alert_only_during_warmup_is_ignored() {
        let events = run_collector(WINDOW, |t| {
            if t < secs(30) {
                firing(ERROR_RATE_RULE, "node0 has a high error rate")
            } else {
                healthy()
            }
        })
        .await;
        assert_eq!(events, vec![AlertEvent::Polled]);
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_alert_is_reported_once() {
        let events = run_collector(WINDOW, |t| {
            if t >= secs(70) {
                firing(VAPI_RATE_RULE, "node1 has a high validator api error rate")
            } else {
                healthy()
            }
        })
        .await;
        assert_eq!(
            events,
            vec![
                AlertEvent::Alert("node1 has a high validator api error rate".to_string()),
                AlertEvent::Polled
            ]
        );
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
    async fn run_stalling(window: Duration, stall_after: Duration) -> Vec<AlertEvent> {
        let token = CancellationToken::new();
        let poller = StallingPoller {
            start: Instant::now(),
            stall_after,
        };
        let mut rx = start_collector(token.clone(), poller);

        time::sleep(window).await;
        token.cancel();

        let drain = async {
            let mut events = Vec::new();
            while let Some(event) = rx.recv().await {
                events.push(event);
            }

            events
        };

        time::timeout(secs(10), drain)
            .await
            .expect("collector did not stop after cancel")
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_poll_during_warmup_stops_on_cancel_without_verdict() {
        let events = run_stalling(WINDOW, secs(1)).await;
        assert!(events.is_empty(), "{events:?}");
    }
}
