//! Validator-stack process sniper.
//!
//! Periodically scans a `/proc`-like filesystem for running Ethereum validator
//! stack processes (beacon nodes, validator clients) and reports the detected
//! component names together with their command lines through a caller-supplied
//! callback. The callback typically feeds a Prometheus metric, but the sniper
//! itself is agnostic to what the callback does.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};

use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use walkdir::WalkDir;

/// Interval between consecutive `/proc` scans.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// Process names that identify Ethereum validator stack processes.
///
/// A detected component's name is the first of these that appears as a
/// substring of the process' command line.
const SUPPORTED_VCS: [&str; 6] = ["lighthouse", "teku", "nimbus", "prysm", "lodestar", "vouch"];

/// Process names that might be interpreters hosting a validator stack
/// component (e.g. lodestar runs under `node`). These pass the initial `comm`
/// filter but only yield a component if their command line matches a
/// [`SUPPORTED_VCS`] entry.
const MAYBE_VCS: [&str; 1] = ["node"];

/// A named process of the Ethereum validator stack running on the machine,
/// whose CLI parameters are read from a `/proc`-like filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackComponent {
    /// The validator stack component name (e.g. `lighthouse`).
    pub name: String,
    /// The process' command line, with arguments joined by single spaces.
    pub cli_params: String,
}

/// Callback invoked after each scan with the detected component names and their
/// CLI parameters as parallel lists (`names[i]` corresponds to
/// `cli_params[i]`).
pub type MetricsFn = Box<dyn Fn(Vec<String>, Vec<String>) + Send + Sync>;

/// A validator-stack process sniper.
pub struct Instance {
    proc_path: PathBuf,
    metrics_fn: MetricsFn,
    interval: Duration,
}

impl std::fmt::Debug for Instance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Instance")
            .field("proc_path", &self.proc_path)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl Instance {
    /// Returns a new sniper for the given `/proc` path and metrics callback,
    /// polling every 15 seconds.
    ///
    /// An empty `proc_path` disables sniping (see [`run`](Self::run)).
    pub fn new(proc_path: impl Into<PathBuf>, metrics_fn: MetricsFn) -> Self {
        Self::new_with_interval(proc_path, metrics_fn, POLL_INTERVAL)
    }

    /// Returns a new sniper for the given `/proc` path, metrics callback and
    /// polling interval.
    ///
    /// An empty `proc_path` disables sniping (see [`run`](Self::run)).
    pub fn new_with_interval(
        proc_path: impl Into<PathBuf>,
        metrics_fn: MetricsFn,
        interval: Duration,
    ) -> Self {
        Self {
            proc_path: proc_path.into(),
            metrics_fn,
            interval,
        }
    }

    /// Polls the `/proc` path every `interval` and reports detected stack
    /// components through the metrics callback, until `ct` is cancelled.
    ///
    /// If the `/proc` path is empty, sniping is disabled and this returns
    /// immediately. All logs emitted while running carry the `stacksnipe`
    /// topic.
    #[tracing::instrument(
        name = "stacksnipe",
        level = "debug",
        skip_all,
        fields(topic = "stacksnipe")
    )]
    pub async fn run(self, ct: CancellationToken) {
        if self.proc_path.as_os_str().is_empty() {
            info!("Stack component sniping disabled");
            return;
        }

        let mut interval = tokio::time::interval(self.interval);
        // Skip the immediate first tick so the first scan happens after one
        // full interval rather than immediately.
        interval.tick().await;

        loop {
            tokio::select! {
                () = ct.cancelled() => return,
                _ = interval.tick() => {
                    let proc_path = self.proc_path.clone();
                    let components = match tokio::task::spawn_blocking(move || snipe(&proc_path)).await {
                        Ok(components) => components,
                        Err(error) => {
                            // spawn_blocking only fails if the scan panics; keep polling.
                            tracing::warn!(?error, "Stack component scan task failed");
                            continue;
                        }
                    };

                    let (names, cli_params): (Vec<String>, Vec<String>) = components
                        .into_iter()
                        .map(|component| (component.name, component.cli_params))
                        .unzip();

                    (self.metrics_fn)(names, cli_params);
                }
            }
        }
    }
}

/// Scans `proc_path` for processes that look like Ethereum validator stack
/// components.
///
/// This is best effort and effectively infallible: every walk or read error is
/// silently skipped.
fn snipe(proc_path: &Path) -> Vec<StackComponent> {
    let mut seen_cmdlines: HashSet<Vec<u8>> = HashSet::new();
    let mut components = Vec::new();

    for entry in WalkDir::new(proc_path).into_iter().filter_map(Result::ok) {
        // Only process directories that look like a PID.
        if !entry.file_type().is_dir() {
            continue;
        }

        let Some(host_pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u64>().ok())
        else {
            continue;
        };

        let proc_dir = entry.path();

        // Initial filter by the process' `comm` (best effort).
        let Ok(comm_bytes) = std::fs::read(proc_dir.join("comm")) else {
            continue;
        };
        let comm = String::from_utf8_lossy(&comm_bytes);
        let comm = comm.trim();

        if !SUPPORTED_VCS.contains(&comm) && !MAYBE_VCS.contains(&comm) {
            continue;
        }

        let Ok(cmdline_bytes) = std::fs::read(proc_dir.join("cmdline")) else {
            continue;
        };

        // The component name comes from the cmdline, not `comm` (e.g. lodestar
        // runs under a `node` process).
        let Some(name) = vc_name(&cmdline_bytes) else {
            continue;
        };

        // Deduplicate by raw cmdline: the same process can appear multiple
        // times (e.g. background threads under `task/`). Checking before the
        // token work below skips that work for repeats.
        if seen_cmdlines.contains(&cmdline_bytes) {
            continue;
        }

        // `/proc/<pid>/cmdline` is NUL-separated; drop empty tokens (including
        // the trailing NUL) and join with single spaces.
        let cli_tokens: Vec<String> = cmdline_bytes
            .split(|&byte| byte == 0)
            .filter(|token| !token.is_empty())
            .map(|token| String::from_utf8_lossy(token).into_owned())
            .collect();

        if cli_tokens.is_empty() {
            continue;
        }

        let cli_params = cli_tokens.join(" ");

        // Record the cmdline now that it's confirmed unique (moved, no clone).
        seen_cmdlines.insert(cmdline_bytes);

        debug!(name, host_pid, cmdline = %cli_params, "Detected stack component");

        components.push(StackComponent {
            name: name.to_owned(),
            cli_params,
        });
    }

    components
}

/// Returns the first [`SUPPORTED_VCS`] name that appears as a substring of the
/// raw command line, or `None` if none match.
///
/// When a command line matches several names, the first in `SUPPORTED_VCS`
/// order wins, so the result is deterministic.
fn vc_name(cmdline: &[u8]) -> Option<&'static str> {
    SUPPORTED_VCS.into_iter().find(|vc| {
        cmdline
            .windows(vc.len())
            .any(|window| window == vc.as_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    /// Writes a fake `/proc/<pid>` entry with the given `comm` and `cmdline`.
    fn populate_proc(base: &Path, pid: u64, comm: &str, cmdline: &[u8]) {
        let proc_dir = base.join(pid.to_string());
        std::fs::create_dir(&proc_dir).expect("create proc dir");
        std::fs::write(proc_dir.join("comm"), comm).expect("write comm");
        std::fs::write(proc_dir.join("cmdline"), cmdline).expect("write cmdline");
    }

    /// Runs an [`Instance`] over `proc_path` with a fast poll, returning the
    /// first `(names, cli_params)` the callback produces, then cancels.
    async fn run_once(proc_path: &Path) -> (Vec<String>, Vec<String>) {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let ct = CancellationToken::new();
        let callback_ct = ct.clone();

        let instance = Instance::new_with_interval(
            proc_path.to_path_buf(),
            Box::new(move |names, cli_params| {
                let _ = tx.send((names, cli_params));
                callback_ct.cancel();
            }),
            Duration::from_millis(20),
        );

        let handle = tokio::spawn(async move { instance.run(ct).await });

        let result = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("metrics callback timed out")
            .expect("metrics channel closed before a result");

        handle.await.expect("run task should join");
        result
    }

    #[tokio::test]
    async fn stack_snipe_happy_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path();

        populate_proc(base, 42, "lighthouse", b"lighthouse_1");
        populate_proc(base, 43, "nimbus", b"nimbus_1");
        // lodestar runs under a `node` process; the name comes from the cmdline.
        populate_proc(base, 44, "node", b"lodestar vc 1");
        // Not part of the validator stack; must be ignored.
        populate_proc(base, 52, "systemd-resolved", b"run_1");

        let (mut names, mut cli_params) = run_once(base).await;
        names.sort();
        cli_params.sort();

        assert_eq!(names, vec!["lighthouse", "lodestar", "nimbus"]);
        assert_eq!(
            cli_params,
            vec!["lighthouse_1", "lodestar vc 1", "nimbus_1"]
        );
    }

    #[tokio::test]
    async fn disabled_when_proc_path_empty() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let ct = CancellationToken::new();

        let instance = Instance::new(
            "",
            Box::new(move |_names, _cli_params| {
                let _ = tx.send(());
            }),
        );

        // Disabled ⇒ `run` returns promptly without ever invoking the callback.
        tokio::time::timeout(Duration::from_secs(1), instance.run(ct))
            .await
            .expect("run should return promptly when disabled");

        assert!(
            rx.try_recv().is_err(),
            "callback must not fire when sniping is disabled"
        );
    }

    #[tokio::test]
    async fn nonexistent_proc_path_emits_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("does-not-exist");

        // The walk yields nothing (no error), so the callback fires with empties.
        let (names, cli_params) = run_once(&missing).await;
        assert!(names.is_empty());
        assert!(cli_params.is_empty());
    }

    #[test]
    fn ignores_non_pid_dirs_and_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path();

        // A directory whose name is not a PID, with otherwise valid contents.
        let not_a_pid = base.join("notapid");
        std::fs::create_dir(&not_a_pid).expect("create dir");
        std::fs::write(not_a_pid.join("comm"), "lighthouse").expect("write comm");
        std::fs::write(not_a_pid.join("cmdline"), b"lighthouse").expect("write cmdline");

        // A file (not a directory) whose name looks like a PID.
        std::fs::write(base.join("44"), b"lighthouse").expect("write file");

        assert!(snipe(base).is_empty());
    }

    #[test]
    fn comm_requires_exact_match() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path();

        // `comm` membership is exact, not substring: this must not match even
        // though both comm and cmdline contain "lighthouse".
        populate_proc(base, 42, "lighthouse-extra", b"lighthouse --datadir /x");

        assert!(snipe(base).is_empty());
    }

    #[test]
    fn maybe_vc_without_supported_substring_ignored() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path();

        // `node` passes the comm filter but its cmdline has no supported VC.
        populate_proc(base, 42, "node", b"node\0server.js");

        assert!(snipe(base).is_empty());
    }

    #[test]
    fn name_derived_from_cmdline_not_comm() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path();

        // comm is `prysm` (supported) but the cmdline only contains `teku`.
        populate_proc(base, 42, "prysm", b"teku\0--network\0mainnet");

        let components = snipe(base);
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "teku");
    }

    #[test]
    fn dedup_identical_cmdlines() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path();

        // Two processes with an identical cmdline (e.g. a thread) dedup to one.
        populate_proc(base, 100, "lighthouse", b"lighthouse\0bn");
        populate_proc(base, 101, "lighthouse", b"lighthouse\0bn");

        assert_eq!(snipe(base).len(), 1);
    }

    #[test]
    fn cmdline_nul_separated_joined_with_spaces() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path();

        // Trailing NUL and inter-argument NULs: empty tokens dropped, joined " ".
        populate_proc(base, 42, "lighthouse", b"lighthouse\0--datadir\0/data\0");

        let components = snipe(base);
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "lighthouse");
        assert_eq!(components[0].cli_params, "lighthouse --datadir /data");
    }

    #[test]
    fn comm_trailing_newline_trimmed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path();

        // Real `/proc/<pid>/comm` has a trailing newline; it must be trimmed.
        populate_proc(base, 42, "lighthouse\n", b"lighthouse\0bn");

        let components = snipe(base);
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "lighthouse");
    }

    #[test]
    fn name_multi_match_deterministic_first() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path();

        // cmdline contains both `lighthouse` and `teku`; the first in
        // SUPPORTED_VCS order (lighthouse) wins, deterministically.
        populate_proc(base, 42, "lighthouse", b"lighthouse\0--also-teku-flag");

        let components = snipe(base);
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "lighthouse");
    }
}
