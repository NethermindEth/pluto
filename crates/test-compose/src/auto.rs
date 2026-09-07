//! The automated flow: define, lock and run a cluster back to back against
//! docker compose, then keep it running while Prometheus is watched for
//! alerts.

use std::{
    fmt, io,
    path::{Path, PathBuf},
    time::Duration,
};

use tokio::{sync::mpsc, task};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    alert::{ALERTS_POLLED, AlertTiming, DockerCurlPoller, start_collector},
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
pub type TmplFn = Box<dyn FnOnce(&mut TmplData) + Send>;

/// Configuration of [`auto`].
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
    /// Adjusts the define step template data.
    pub define_tmpl_fn: Option<TmplFn>,
    /// Append the `docker compose up` output to this file instead of stdout.
    pub log_file: Option<PathBuf>,
    /// Options of the define step.
    pub define_options: DefineOptions,
    /// Alert collector cadence.
    pub timing: AlertTiming,
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
            define_tmpl_fn: None,
            log_file: None,
            define_options: DefineOptions::default(),
            timing: AlertTiming::default(),
        }
    }
}

impl fmt::Debug for AutoConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutoConfig")
            .field("dir", &self.dir)
            .field("alert_timeout", &self.alert_timeout)
            .field("sudo_perms", &self.sudo_perms)
            .field("print_yml", &self.print_yml)
            .field("run_tmpl_fn", &self.run_tmpl_fn.is_some())
            .field("define_tmpl_fn", &self.define_tmpl_fn.is_some())
            .field("log_file", &self.log_file)
            .field("define_options", &self.define_options)
            .field("timing", &self.timing)
            .finish()
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
        define_tmpl_fn,
        log_file,
        define_options,
        timing,
    } = conf;

    let mut sink = LogSink::open(log_file.as_deref())?;
    let never = CancellationToken::new();
    let step = StepRunner {
        dir: &dir,
        sudo_perms,
        print_yml,
    };

    step.run("define", define_tmpl_fn, move |dir: &Path, conf| {
        define(dir, conf, &define_options)
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

    // Ensure everything is clean before the alert test starts.
    let _ = down(&dir, sudo_perms).await;

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

    let mut alerts = start_collector(token.clone(), DockerCurlPoller::new(&dir), timing);

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
    alerts: &mut mpsc::Receiver<String>,
) -> Result<()> {
    match up(dir, sink, token).await? {
        // `--abort-on-container-exit` exits 0 when a container stops cleanly,
        // taking the whole cluster down with it. Nothing was observed for the
        // full window, so this is a failure rather than "no alerts detected".
        UpOutcome::Exited if !alert_timeout.is_zero() => return Err(ComposeError::ClusterStopped),
        // Without a window the cluster ran to completion. Stop the collector
        // so the channel drains and a verdict can be reached.
        UpOutcome::Exited => token.cancel(),
        UpOutcome::Cancelled => {}
    }

    let mut detected = Vec::new();
    let mut polled = false;
    while let Some(alert) = alerts.recv().await {
        if alert == ALERTS_POLLED {
            polled = true;
        } else {
            detected.push(alert);
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
        let mut tmpl = run_step(name, self.dir, false, run_fn).await?;

        if self.sudo_perms {
            fix_perms(self.dir).await?;
        }

        if let Some(tmpl_fn) = tmpl_fn {
            tmpl_fn(&mut tmpl);
            write_docker_compose(self.dir, &tmpl)?;
        }

        if self.print_yml {
            print_docker_compose(self.dir).await?;
        }

        Ok(())
    }
}

/// Loads the config in `dir`, runs the generator step `run_fn` on it and,
/// when `up_after` is set, brings the resulting cluster up on stdout. `topic`
/// names the step in the log.
pub async fn run_step<F>(
    topic: &'static str,
    dir: impl AsRef<Path>,
    up_after: bool,
    run_fn: F,
) -> Result<TmplData>
where
    F: FnOnce(&Path, Config) -> Result<TmplData> + Send + 'static,
{
    let dir = dir.as_ref().to_path_buf();

    let conf = match load_config(&dir) {
        Err(ComposeError::LoadConfig(err)) if err.kind() == io::ErrorKind::NotFound => {
            return Err(ComposeError::ConfigNotFound {
                dir: dir.display().to_string(),
            });
        }
        other => other?,
    };

    info!(command = topic, "Running compose command");

    let step_dir = dir.clone();
    let tmpl = task::spawn_blocking(move || run_fn(&step_dir, conf))
        .await
        .map_err(|err| {
            if err.is_panic() {
                std::panic::resume_unwind(err.into_panic())
            } else {
                ComposeError::StepCancelled(err)
            }
        })??;

    if up_after {
        up(&dir, &LogSink::Stdout, &CancellationToken::new()).await?;
    }

    Ok(tmpl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Step, write_config};

    #[tokio::test]
    async fn run_step_without_config_reports_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");

        let err = run_step("lock", dir.path(), false, |dir: &Path, conf| {
            lock(dir, conf)
        })
        .await
        .expect_err("missing config must fail");

        assert_eq!(
            err.to_string(),
            format!(
                "compose config.json not found; write one with WriteConfig or New first: dir={}",
                dir.path().display()
            )
        );
    }

    #[tokio::test]
    async fn run_step_runs_the_generator_on_the_loaded_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(dir.path(), &Config::new_default()).expect("write config");

        let err = run_step("lock", dir.path(), false, |dir: &Path, conf| {
            lock(dir, conf)
        })
        .await
        .expect_err("lock on a new config must fail");

        assert!(
            matches!(err, ComposeError::NotDefined { step: Step::New }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn run_step_surfaces_other_load_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("config.json"), "{").expect("write broken config");

        let err = run_step("lock", dir.path(), false, |dir: &Path, conf| {
            lock(dir, conf)
        })
        .await
        .expect_err("broken config must fail");

        assert!(matches!(err, ComposeError::UnmarshalConfig(_)), "{err:?}");
    }

    #[test]
    fn auto_config_defaults() {
        let conf = AutoConfig::new("/tmp/compose");

        assert_eq!(conf.dir, PathBuf::from("/tmp/compose"));
        assert_eq!(conf.alert_timeout, Duration::ZERO);
        assert!(!conf.sudo_perms);
        assert!(!conf.print_yml);
        assert!(conf.run_tmpl_fn.is_none());
        assert!(conf.define_tmpl_fn.is_none());
        assert!(conf.log_file.is_none());
        assert!(conf.define_options.pull_images);
        assert_eq!(conf.timing, AlertTiming::default());
        assert!(format!("{conf:?}").contains("run_tmpl_fn: false"));
    }
}
