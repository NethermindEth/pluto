use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "dkg-stress",
    about = "Run N DKG ceremonies (back-to-back or in parallel) with a live ratatui UI.",
    long_about = "Wraps scripts/dkg-runner/run.sh, dispatching N runs across W parallel \
                  workers with isolated WORK_DIRs. Per-run config (NODES, THRESHOLD, \
                  PLUTO_NODES, CHARON_NODES, TIMEOUT, etc.) is forwarded to run.sh \
                  via the inherited environment — see run.sh --help for the full list."
)]
pub struct Cli {
    /// Total number of ceremonies to run.
    #[arg(short = 'n', long, env = "RUNS", default_value_t = 10)]
    pub runs: u32,

    /// Number of ceremonies in flight at the same time.
    #[arg(short = 'w', long, env = "WORKERS", default_value_t = 1)]
    pub workers: u32,

    /// Base directory; each run uses run-NNNN/ inside it.
    #[arg(long, env = "STRESS_WORK_DIR", default_value = "/tmp/dkg-stress")]
    pub work_dir: PathBuf,

    /// Path to scripts/dkg-runner/run.sh. Defaults to the script next to the
    /// repo's checked-in copy, resolved relative to the binary's location.
    #[arg(long, env = "DKG_RUN_SCRIPT")]
    pub run_script: Option<PathBuf>,

    /// Keep full per-run dirs even on success. By default, node-*/ subdirs of
    /// passed runs are deleted to save disk; failed run dirs are always kept.
    #[arg(long, env = "KEEP_PASSED")]
    pub keep_passed: bool,

    /// Disable the ratatui UI; emit per-run log lines instead. Auto-enabled
    /// when stdout isn't a TTY or CI is set.
    #[arg(long, env = "NO_TUI")]
    pub no_tui: bool,

    /// UI tick rate in milliseconds (how often the table redraws and elapsed
    /// counters advance). Lower = smoother but more CPU.
    #[arg(long, env = "TICK_MS", default_value_t = 250)]
    pub tick_ms: u64,
}
