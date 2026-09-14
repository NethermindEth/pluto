//! The automated flow: define, lock and run a cluster back to back against
//! docker compose, then keep it running while Prometheus is watched for
//! alerts.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use tokio::{sync::mpsc, task};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    alert::{AlertEvent, DockerCurlPoller, start_collector},
    config::{Config, load_config},
    define::{DefineOptions, define},
    error::{ComposeError, Result},
    lock::lock,
    process::{LogSink, UpOutcome, build_and_create, down, fix_perms, print_docker_compose, up},
    run::run,
    template::{TmplData, write_docker_compose},
};

/// Hook that adjusts a step's template data before `docker-compose.yml` is
/// rewritten.
pub type TmplFn = fn(&mut TmplData);

/// Configuration of [`auto`].
#[derive(Debug, Clone)]
pub struct AutoConfig {
    /// The compose directory holding `config.json`.
    pub dir: PathBuf,
    /// How long to keep the cluster running while collecting alerts. Zero
    /// runs the cluster until it exits on its own.
    pub alert_timeout: Duration,
    /// Fix artefact permissions with `sudo` after each step and before each
    /// `docker compose down`.
    pub sudo_perms: bool,
    /// Print `docker-compose.yml` after each step.
    pub print_yml: bool,
    /// Adjusts the run step template data.
    pub run_tmpl_fn: Option<TmplFn>,
    /// Append the `docker compose up` output to this file instead of stdout.
    pub log_file: Option<PathBuf>,
}

impl AutoConfig {
    /// A config for compose directory `dir` with everything else at its
    /// defaults: no alert window, no sudo, no printing, stdout logging.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            alert_timeout: Duration::ZERO,
            sudo_perms: false,
            print_yml: false,
            run_tmpl_fn: None,
            log_file: None,
        }
    }
}

/// Runs the define, lock and run steps in `conf.dir`, brings the cluster up
/// and, when `alert_timeout` is set, keeps it running for that long while
/// polling Prometheus. Fails when the cluster stops early, when Prometheus
/// could not be polled through the end of the window, or when alerts fired.
///
/// The cluster is torn down with `docker compose down` before returning.
pub async fn auto(conf: AutoConfig) -> Result<()> {
    let AutoConfig {
        dir,
        alert_timeout,
        sudo_perms,
        print_yml,
        run_tmpl_fn,
        log_file,
    } = conf;

    let mut sink = LogSink::open(log_file.as_deref())?;
    let never = CancellationToken::new();
    let step = StepRunner {
        dir: &dir,
        sudo_perms,
        print_yml,
    };

    step.run("define", None, |dir: &Path, conf| {
        define(dir, conf, &DefineOptions::default())
    })
    .await?;
    sink.banner("===== define step: docker compose up =====\n");
    up(&dir, &sink, &never).await?;

    step.run("lock", None, |dir: &Path, conf| lock(dir, conf))
        .await?;
    sink.banner("===== lock step: docker compose up =====\n");
    up(&dir, &sink, &never).await?;

    step.run("run", run_tmpl_fn, |dir: &Path, conf| run(dir, conf))
        .await?;

    // Ensure everything is clean before the alert test starts. Permissions
    // were fixed right after the run step, so plain down suffices here.
    let _ = down(&dir, false).await;

    sink.banner("===== run step: docker compose up --no-start --build =====\n");
    build_and_create(&dir).await?;

    let token = CancellationToken::new();
    if !alert_timeout.is_zero() {
        let deadline = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(alert_timeout).await;
            deadline.cancel();
        });
    }

    let mut alerts = start_collector(token.clone(), DockerCurlPoller::new(&dir));

    sink.banner("===== run step: docker compose up =====\n");
    let result = observe(&dir, &sink, &token, alert_timeout, &mut alerts).await;

    let _ = down(&dir, sudo_perms).await;
    token.cancel();

    result
}

/// Brings the cluster up and turns the collected alerts into a verdict.
async fn observe(
    dir: &Path,
    sink: &LogSink,
    token: &CancellationToken,
    alert_timeout: Duration,
    alerts: &mut mpsc::Receiver<AlertEvent>,
) -> Result<()> {
    match up(dir, sink, token).await? {
        // `--abort-on-container-exit` exits 0 when a container stops cleanly;
        // the window was not observed, so this is a failure, not "no alerts".
        UpOutcome::Exited if !alert_timeout.is_zero() => return Err(ComposeError::ClusterStopped),
        // Without a window the cluster ran to completion. Stop the collector
        // so the channel drains and a verdict can be reached.
        UpOutcome::Exited => token.cancel(),
        UpOutcome::Cancelled => {}
    }

    let mut detected = Vec::new();
    let mut polled = false;
    while let Some(event) = alerts.recv().await {
        match event {
            AlertEvent::Alert(alert) => detected.push(alert),
            AlertEvent::Polled => polled = true,
        }
    }

    if !polled {
        return Err(ComposeError::PrometheusNotPolled);
    }
    if !detected.is_empty() {
        return Err(ComposeError::AlertsDetected { alerts: detected });
    }

    info!("No alerts detected");

    Ok(())
}

/// The per-step work shared by define, lock and run.
struct StepRunner<'a> {
    dir: &'a Path,
    sudo_perms: bool,
    print_yml: bool,
}

impl StepRunner<'_> {
    async fn run<F>(&self, name: &'static str, tmpl_fn: Option<TmplFn>, run_fn: F) -> Result<()>
    where
        F: FnOnce(&Path, Config) -> Result<TmplData> + Send + 'static,
    {
        let mut tmpl = run_step(name, self.dir, run_fn).await?;

        if self.sudo_perms {
            fix_perms(self.dir).await?;
        }

        if let Some(tmpl_fn) = tmpl_fn {
            tmpl_fn(&mut tmpl);
            write_docker_compose(self.dir, &tmpl)?;
        }

        if self.print_yml {
            print_docker_compose(self.dir)?;
        }

        Ok(())
    }
}

/// Loads the config in `dir` and runs the generator step `run_fn` on it off
/// the async runtime. `topic` names the step in the log.
async fn run_step<F>(topic: &'static str, dir: &Path, run_fn: F) -> Result<TmplData>
where
    F: FnOnce(&Path, Config) -> Result<TmplData> + Send + 'static,
{
    let conf = load_config(dir)?;

    info!(command = topic, "Running compose command");

    let step_dir = dir.to_path_buf();
    task::spawn_blocking(move || run_fn(&step_dir, conf))
        .await
        .map_err(|err| {
            if err.is_panic() {
                std::panic::resume_unwind(err.into_panic())
            } else {
                ComposeError::StepCancelled(err)
            }
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Step, write_config};

    #[tokio::test]
    async fn run_step_runs_the_generator_on_the_loaded_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(dir.path(), &Config::new_default()).expect("write config");

        let err = run_step("lock", dir.path(), |dir: &Path, conf| lock(dir, conf))
            .await
            .expect_err("lock on a new config must fail");

        assert!(
            matches!(err, ComposeError::NotDefined { step: Step::New }),
            "{err:?}"
        );
    }
}
