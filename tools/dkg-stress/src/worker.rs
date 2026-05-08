use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::state::{App, RunState};

/// Set of process-group IDs (== PIDs since we put each child in its own
/// group) for in-flight run.sh invocations. The UI thread uses this on
/// shutdown to SIGTERM the whole tree per ceremony.
pub type Killers = Arc<Mutex<HashSet<u32>>>;

pub fn spawn_workers(
    config: Arc<Config>,
    app: Arc<Mutex<App>>,
    stop: Arc<AtomicBool>,
    killers: Killers,
) -> Vec<JoinHandle<()>> {
    let counter = Arc::new(AtomicU32::new(1));
    (0..config.workers)
        .map(|_| {
            let config = config.clone();
            let app = app.clone();
            let stop = stop.clone();
            let killers = killers.clone();
            let counter = counter.clone();
            thread::spawn(move || worker_loop(config, app, stop, killers, counter))
        })
        .collect()
}

fn worker_loop(
    config: Arc<Config>,
    app: Arc<Mutex<App>>,
    stop: Arc<AtomicBool>,
    killers: Killers,
    counter: Arc<AtomicU32>,
) {
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let id = counter.fetch_add(1, Ordering::Relaxed);
        if id > config.runs {
            return;
        }
        if let Err(err) = run_one(id, &config, &app, &killers) {
            // Worker errors (spawn failures, fs errors, etc.) are recorded as
            // failures via the App update inside run_one's error path; this
            // arm only fires when even that bookkeeping failed. Print to
            // stderr so it shows up after the TUI is restored.
            eprintln!("[run-{:04}] worker error: {:#}", id, err);
        }
    }
}

fn run_one(id: u32, config: &Config, app: &Mutex<App>, killers: &Killers) -> Result<()> {
    let label = format!("run-{:04}", id);
    let run_dir = config.work_dir.join(&label);
    let _ = fs::remove_dir_all(&run_dir);
    fs::create_dir_all(&run_dir)?;

    let log_path = run_dir.join("run.log");
    let log_file = fs::File::create(&log_path)?;
    let log_clone = log_file.try_clone()?;

    let started = Instant::now();
    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let started_iso = format_iso_utc(started_unix);

    set_state(app, id, RunState::Running { started_at: started });

    let mut cmd = Command::new(&config.run_script);
    cmd.env("WORK_DIR", &run_dir)
        .env("CI", &config.worker_ci)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_clone))
        .stdin(Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Make the child a process-group leader so we can SIGTERM the whole
        // tree (run.sh + its node children) with kill(-pgid, SIGTERM).
        cmd.process_group(0);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            set_state(app, id, RunState::Fail { duration_s: 0 });
            config.append_summary_line(&label, "fail", 0, &started_iso, &run_dir)?;
            return Err(e.into());
        }
    };

    let pid = child.id();
    insert_killer(killers, pid);

    let wait_result = child.wait();
    remove_killer(killers, pid);

    let duration_s = started.elapsed().as_secs();
    let pass = wait_result.map(|s| s.success()).unwrap_or(false);

    let final_state = if pass {
        RunState::Pass { duration_s }
    } else {
        RunState::Fail { duration_s }
    };
    set_state(app, id, final_state);

    let status_str = if pass { "pass" } else { "fail" };
    config.append_summary_line(&label, status_str, duration_s, &started_iso, &run_dir)?;

    if pass && !config.keep_passed {
        prune_node_dirs(&run_dir);
    }

    Ok(())
}

fn set_state(app: &Mutex<App>, id: u32, state: RunState) {
    if let Ok(mut a) = app.lock() {
        let idx = (id as usize).saturating_sub(1);
        if let Some(slot) = a.runs.get_mut(idx) {
            *slot = state;
        }
    }
}

fn insert_killer(killers: &Killers, pid: u32) {
    if let Ok(mut k) = killers.lock() {
        k.insert(pid);
    }
}

fn remove_killer(killers: &Killers, pid: u32) {
    if let Ok(mut k) = killers.lock() {
        k.remove(&pid);
    }
}

/// Drop node-*/ subdirectories of a passed run to keep disk usage bounded.
/// run.log and the cluster-lock outputs are kept for verification.
fn prune_node_dirs(run_dir: &std::path::Path) {
    let Ok(entries) = fs::read_dir(run_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("node-") {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// Send SIGTERM to every registered process group, then SIGKILL stragglers
/// after a short grace period.
pub fn kill_all(killers: &Killers, grace: Duration) {
    let pids: Vec<u32> = killers.lock().map(|k| k.iter().copied().collect()).unwrap_or_default();
    if pids.is_empty() {
        return;
    }
    for pid in &pids {
        send_signal(*pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        let remaining = killers.lock().map(|k| k.len()).unwrap_or(0);
        if remaining == 0 {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let remaining: Vec<u32> = killers.lock().map(|k| k.iter().copied().collect()).unwrap_or_default();
    for pid in remaining {
        send_signal(pid, libc::SIGKILL);
    }
}

#[cfg(unix)]
fn send_signal(pid: u32, sig: libc::c_int) {
    // Negate the PID to address the whole process group. Each child was
    // spawned with process_group(0), making it the group leader (so PID ==
    // PGID). Negative values to libc::kill mean "every process in this
    // group". This is the kernel's standard mechanism for taking down a
    // shell-launched subtree (run.sh + the four DKG nodes it forked).
    //
    // Cast safety: PIDs fit in i32 on every Unix we target.
    let signed: i32 = pid.try_into().unwrap_or(0);
    if signed > 0 {
        // SAFETY: kill is a pure libc syscall with no aliasing or memory
        // requirements; we pass a valid signal number. Out-of-range signed
        // we already filtered above. Errors (ESRCH if the process is gone)
        // are acceptable and ignored.
        unsafe {
            libc::kill(-signed, sig);
        }
    }
}

#[cfg(not(unix))]
fn send_signal(_pid: u32, _sig: libc::c_int) {
    // No-op on non-Unix; the tool only targets Unix anyway (run.sh is bash).
}

fn format_iso_utc(unix_secs: u64) -> String {
    // RFC3339 / ISO-8601 in UTC without external chrono dep.
    // Range covers years 1970..9999 which is plenty for log timestamps.
    let secs = unix_secs as i64;
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let h = (time / 3600) as u32;
    let m = ((time % 3600) / 60) as u32;
    let s = (time % 60) as u32;
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, h, m, s
    )
}

/// Convert days since 1970-01-01 to (year, month, day) using the proleptic
/// Gregorian calendar (Howard Hinnant's algorithm).
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days.saturating_add(719_468);
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d)
}
