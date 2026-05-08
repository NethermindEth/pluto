use anyhow::{Context, Result, bail};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::cli::Cli;

/// Resolved configuration shared across worker threads. All fields are
/// immutable after construction; mutable shared state lives on `App` instead.
pub struct Config {
    pub runs: u32,
    pub workers: u32,
    pub work_dir: PathBuf,
    pub run_script: PathBuf,
    pub keep_passed: bool,
    pub no_tui: bool,
    pub tick_ms: u64,
    pub worker_ci: String,
    pub summary_path: PathBuf,
    /// Serialised writer for the TSV summary (multiple workers append to it).
    pub summary: Mutex<BufWriter<fs::File>>,
}

impl Config {
    pub fn from_cli(cli: Cli) -> Result<Self> {
        if cli.runs == 0 {
            bail!("RUNS must be >= 1 (got {})", cli.runs);
        }
        if cli.workers == 0 {
            bail!("WORKERS must be >= 1 (got {})", cli.workers);
        }
        let workers = cli.workers.min(cli.runs);

        let run_script = match cli.run_script {
            Some(p) => p,
            None => default_run_script()?,
        };
        let run_script = run_script
            .canonicalize()
            .with_context(|| format!("run script not found: {}", run_script.display()))?;
        if !run_script.is_file() {
            bail!("run script is not a regular file: {}", run_script.display());
        }

        // Force CI=true for parallel runs so per-node logs don't tee to the
        // controlling terminal (run.sh suppresses tee under CI). Honour any
        // existing CI value the user explicitly set.
        let worker_ci = match std::env::var("CI") {
            Ok(v) if !v.is_empty() => v,
            _ if workers > 1 => "true".to_string(),
            _ => String::new(),
        };

        fs::create_dir_all(&cli.work_dir)
            .with_context(|| format!("create work dir {}", cli.work_dir.display()))?;
        let summary_path = cli.work_dir.join("summary.tsv");
        let summary_file = fs::File::create(&summary_path)
            .with_context(|| format!("create summary file {}", summary_path.display()))?;
        let mut summary = BufWriter::new(summary_file);
        writeln!(summary, "run_id\tstatus\tduration_s\tstart_time\twork_dir")?;
        summary.flush()?;

        Ok(Self {
            runs: cli.runs,
            workers,
            work_dir: cli.work_dir,
            run_script,
            keep_passed: cli.keep_passed,
            no_tui: cli.no_tui,
            tick_ms: cli.tick_ms.max(50),
            worker_ci,
            summary_path,
            summary: Mutex::new(summary),
        })
    }

    pub fn append_summary_line(
        &self,
        label: &str,
        status: &str,
        duration_s: u64,
        start_time_iso: &str,
        run_dir: &Path,
    ) -> Result<()> {
        let mut w = self
            .summary
            .lock()
            .map_err(|_| anyhow::anyhow!("summary writer lock poisoned"))?;
        writeln!(
            w,
            "{}\t{}\t{}\t{}\t{}",
            label,
            status,
            duration_s,
            start_time_iso,
            run_dir.display()
        )?;
        w.flush()?;
        Ok(())
    }
}

/// Locate scripts/dkg-runner/run.sh relative to either the running binary
/// (when invoked from a checkout) or CWD as a final fallback.
fn default_run_script() -> Result<PathBuf> {
    // The crate lives at <repo>/tools/dkg-stress; the script lives at
    // <repo>/scripts/dkg-runner/run.sh. Cargo sets CARGO_MANIFEST_DIR at
    // compile time so we know the crate's location regardless of how the
    // binary is launched.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let candidate = Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("scripts")
        .join("dkg-runner")
        .join("run.sh");
    if candidate.exists() {
        return Ok(candidate);
    }
    bail!(
        "could not find run.sh at {} — pass --run-script or set DKG_RUN_SCRIPT",
        candidate.display()
    )
}
