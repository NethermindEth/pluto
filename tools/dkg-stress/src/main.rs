//! DKG stress runner with a ratatui-based UI.
//!
//! Wraps `scripts/dkg-runner/run.sh` to execute N ceremonies, optionally in
//! parallel, with live status visualisation. Per-run config (NODES, THRESHOLD,
//! PLUTO_NODES, CHARON_NODES, TIMEOUT, …) is forwarded via the inherited
//! environment — see `run.sh --help`.

mod cli;
mod config;
mod logs;
mod state;
mod ui;
mod worker;

use anyhow::Result;
use clap::Parser;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::cli::Cli;
use crate::config::Config;
use crate::state::{App, RunState};
use crate::worker::{spawn_workers, kill_all};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Arc::new(Config::from_cli(cli)?);

    let app = Arc::new(Mutex::new(App::new(config.runs as usize)));
    let stop = Arc::new(AtomicBool::new(false));
    install_signal_handlers(&stop)?;
    let killers = Arc::new(Mutex::new(HashSet::new()));

    let workers = spawn_workers(config.clone(), app.clone(), stop.clone(), killers.clone());

    // Auto-disable the TUI when stdout isn't a TTY (piped/redirected) — the
    // alt-screen escapes would garble the captured output. The explicit
    // --no-tui flag overrides regardless.
    let use_tui = !config.no_tui && is_tty_stdout();

    if use_tui {
        let workers_done = make_done_check(&workers);
        ui::run_tui(
            config.clone(),
            app.clone(),
            stop.clone(),
            killers.clone(),
            workers_done,
        )?;
    } else {
        run_logging(&config, &app, &stop, &workers);
    }

    // Whatever path got us here (TUI quit, all workers finished, or the
    // logging loop returned), make sure no children outlive us and the
    // worker threads have a chance to drain their final-state writes.
    if !workers
        .iter()
        .all(|h| h.is_finished())
    {
        stop.store(true, Ordering::Relaxed);
        kill_all(&killers, Duration::from_secs(5));
    }
    for h in workers {
        let _ = h.join();
    }

    print_final_summary(&config, &app);

    let any_fail = match app.lock() {
        Ok(a) => a.runs.iter().any(|s| matches!(s, RunState::Fail { .. })),
        Err(_) => true,
    };
    if any_fail {
        std::process::exit(1);
    }
    Ok(())
}

fn make_done_check(workers: &[JoinHandle<()>]) -> impl Fn() -> bool + '_ {
    move || workers.iter().all(|h| h.is_finished())
}

/// Replace the default termination handlers so SIGINT/SIGTERM/SIGHUP flip
/// the shared stop flag instead of killing us outright. This lets the TUI
/// restore the terminal and the dispatch path SIGTERM in-flight ceremonies
/// before we exit, regardless of whether the signal arrived from a tty
/// Ctrl-C (no-tui mode) or an external `kill`.
#[cfg(unix)]
fn install_signal_handlers(stop: &Arc<AtomicBool>) -> Result<()> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    for sig in [SIGINT, SIGTERM, SIGHUP] {
        signal_hook::flag::register(sig, stop.clone())?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_signal_handlers(_stop: &Arc<AtomicBool>) -> Result<()> {
    Ok(())
}

fn is_tty_stdout() -> bool {
    // SAFETY: isatty is a pure libc syscall taking an fd; STDOUT_FILENO is
    // always a valid file descriptor for our process.
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

/// Append-only fallback for non-TTY / `--no-tui` runs. Polls App state and
/// emits one line per state transition, plus a heartbeat counter.
fn run_logging(
    config: &Config,
    app: &Mutex<App>,
    stop: &AtomicBool,
    workers: &[JoinHandle<()>],
) {
    eprintln!(
        "dkg-stress: runs={} workers={} work_dir={}",
        config.runs,
        config.workers,
        config.work_dir.display()
    );
    let total = config.runs as usize;
    let mut last: Vec<RunStateTag> = vec![RunStateTag::Pending; total];

    loop {
        let snapshot: Vec<RunState> = match app.lock() {
            Ok(a) => a.runs.clone(),
            Err(_) => return,
        };
        for (i, state) in snapshot.iter().enumerate() {
            let tag = tag(state);
            if tag != last[i] {
                emit_transition(i + 1, state);
                last[i] = tag;
            }
        }
        if workers.iter().all(|h| h.is_finished()) {
            return;
        }
        if stop.load(Ordering::Relaxed) {
            eprintln!("dkg-stress: caught signal — terminating in-flight ceremonies");
            return;
        }
        thread::sleep(Duration::from_millis(config.tick_ms));
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RunStateTag {
    Pending,
    Running,
    Pass,
    Fail,
}

fn tag(s: &RunState) -> RunStateTag {
    match s {
        RunState::Pending => RunStateTag::Pending,
        RunState::Running { .. } => RunStateTag::Running,
        RunState::Pass { .. } => RunStateTag::Pass,
        RunState::Fail { .. } => RunStateTag::Fail,
    }
}

fn emit_transition(id: usize, state: &RunState) {
    match state {
        RunState::Pending => {}
        RunState::Running { .. } => {
            println!("[run-{:04}] starting", id);
        }
        RunState::Pass { duration_s } => {
            println!("[run-{:04}] PASS in {}s", id, duration_s);
        }
        RunState::Fail { duration_s } => {
            eprintln!("[run-{:04}] FAIL after {}s", id, duration_s);
        }
    }
}

fn print_final_summary(config: &Config, app: &Mutex<App>) {
    let snapshot: Vec<RunState> = match app.lock() {
        Ok(a) => a.runs.clone(),
        Err(_) => return,
    };
    let mut passed = 0u64;
    let mut failed = 0u64;
    let mut pending = 0u64;
    let mut min_d = u64::MAX;
    let mut max_d = 0u64;
    let mut sum_d = 0u64;
    let mut n_d = 0u64;
    for s in &snapshot {
        match s {
            RunState::Pass { duration_s } => {
                passed += 1;
                update_stats(*duration_s, &mut min_d, &mut max_d, &mut sum_d, &mut n_d);
            }
            RunState::Fail { duration_s } => {
                failed += 1;
                update_stats(*duration_s, &mut min_d, &mut max_d, &mut sum_d, &mut n_d);
            }
            _ => pending += 1,
        }
    }

    println!("==============================================");
    println!("dkg-stress complete");
    println!("  Passed:  {}/{}", passed, snapshot.len());
    println!("  Failed:  {}/{}", failed, snapshot.len());
    if pending > 0 {
        println!("  Skipped: {} (aborted before they ran)", pending);
    }
    if n_d > 0 {
        let mean = (sum_d as f64) / (n_d as f64);
        println!("  Duration min/mean/max = {}s / {:.1}s / {}s", min_d, mean, max_d);
    }
    println!("  Summary: {}", config.summary_path.display());

    if failed > 0 {
        println!("Failed runs:");
        for (i, s) in snapshot.iter().enumerate() {
            if let RunState::Fail { duration_s } = s {
                let label = format!("run-{:04}", i + 1);
                let dir = config.work_dir.join(&label);
                println!("  {}  ({}s)  {}", label, duration_s, dir.display());
            }
        }
    }
    println!("==============================================");

    // Suppress unused-import warning when we only conditionally read Instant.
    let _ = Instant::now;
}

fn update_stats(d: u64, min_d: &mut u64, max_d: &mut u64, sum_d: &mut u64, n: &mut u64) {
    if d < *min_d {
        *min_d = d;
    }
    if d > *max_d {
        *max_d = d;
    }
    *sum_d = sum_d.saturating_add(d);
    *n = n.saturating_add(1);
}
