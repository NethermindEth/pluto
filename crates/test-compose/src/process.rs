//! Docker compose process control for the automated flow: bring clusters up
//! and down, build images, fix artefact permissions and print the compose file.
//!
//! Every command is resolved through `PATH` and run in the compose directory.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::Stdio,
};

use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::error::{CommandError, ComposeError, Result};

/// Destination of the `docker compose up` output: the stdout of this process
/// or an append-only log file.
#[derive(Debug)]
pub enum LogSink {
    /// Write to the stdout of this process.
    Stdout,
    /// Append to a log file.
    File(File),
}

impl LogSink {
    /// Opens `path` for appending, creating it with mode `0o644`, or writes to
    /// stdout when `path` is `None`.
    pub fn open(path: Option<&Path>) -> Result<Self> {
        match path {
            None => Ok(Self::Stdout),
            Some(path) => OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o644)
                .open(path)
                .map(Self::File)
                .map_err(ComposeError::io("open log file")),
        }
    }

    /// Writes a step banner. Write failures are ignored: the banner only helps
    /// a reader find their way through the log.
    pub fn banner(&mut self, text: impl AsRef<str>) {
        let text = text.as_ref().as_bytes();
        match self {
            Self::Stdout => {
                let mut stdout = io::stdout().lock();
                let _ = stdout.write_all(text);
                let _ = stdout.flush();
            }
            Self::File(file) => {
                let _ = file.write_all(text);
            }
        }
    }

    /// A child-process output handle writing into this sink. Both stdout and
    /// stderr of the child are pointed here, so with [`LogSink::Stdout`] the
    /// child's stderr lands on this process's stdout.
    fn stdio(&self) -> io::Result<Stdio> {
        match self {
            Self::Stdout => Ok(Stdio::from(io::stdout())),
            Self::File(file) => file.try_clone().map(Stdio::from),
        }
    }
}

/// How `docker compose up` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpOutcome {
    /// The cluster exited on its own with a zero status.
    Exited,
    /// The cluster was killed because the cancellation token fired.
    Cancelled,
}

/// Prints `docker-compose.yml` from `dir` to stdout.
pub fn print_docker_compose(dir: impl AsRef<Path>) -> Result<()> {
    info!("Printing docker-compose.yml");

    let yml = fs::read(dir.as_ref().join("docker-compose.yml"))
        .map_err(ComposeError::io("read docker-compose.yml"))?;

    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&yml)
        .and_then(|()| stdout.flush())
        .map_err(ComposeError::io("print docker-compose.yml"))
}

/// Hands the compose artefacts back to the current user. Containers run as
/// root and leave root-owned files behind, so this runs
/// `sudo chown -R <uid>:<gid> .` followed by `sudo chmod -R a+wrX .` in `dir`.
pub async fn fix_perms(dir: impl AsRef<Path>) -> Result<()> {
    let dir = dir.as_ref();
    let owner = format!("{}:{}", nix::unistd::getuid(), nix::unistd::getgid());
    let commands: [(&str, [&str; 3]); 2] = [
        ("chown", ["-R", owner.as_str(), "."]),
        ("chmod", ["-R", "a+wrX", "."]),
    ];

    for (program, args) in commands {
        let status = Command::new("sudo")
            .arg(program)
            .args(args)
            .current_dir(dir)
            .status()
            .await;

        CommandError::check(status).map_err(ComposeError::exec(format!("exec sudo {program}")))?;
    }

    Ok(())
}

/// Stops and removes the cluster with
/// `docker compose down --remove-orphans --timeout=2`, preceded by
/// [`fix_perms`] when `sudo_perms` is set.
pub async fn down(dir: impl AsRef<Path>, sudo_perms: bool) -> Result<()> {
    let dir = dir.as_ref();
    if sudo_perms {
        fix_perms(dir).await?;
    }

    info!("Executing docker compose down");

    let status = Command::new("docker")
        .args(["compose", "down", "--remove-orphans", "--timeout=2"])
        .current_dir(dir)
        .status()
        .await;

    CommandError::check(status).map_err(ComposeError::exec("run down"))
}

/// Builds the images in parallel, then runs `docker compose up` with its
/// output going to `sink` until the cluster exits or `token` is cancelled.
///
/// Cancellation kills the process and reports [`UpOutcome::Cancelled`], also
/// when the killed process reports a failing exit status. A cancellation that
/// interrupts the build is an error, as the build never produced a cluster.
pub async fn up(
    dir: impl AsRef<Path>,
    sink: &LogSink,
    token: &CancellationToken,
) -> Result<UpOutcome> {
    let dir = dir.as_ref();

    info!("Executing docker compose build");

    let mut build = Command::new("docker");
    build
        .args(["compose", "build", "--parallel"])
        .current_dir(dir)
        .kill_on_drop(true);

    let output = token
        .run_until_cancelled(build.output())
        .await
        .unwrap_or_else(|| Err(io::Error::other("signal: killed")));
    CommandError::check_output(output).map_err(ComposeError::exec("exec docker compose build"))?;

    info!("Executing docker compose up");

    const UP: &str = "exec docker compose up";

    let mut child = Command::new("docker")
        .args([
            "compose",
            "up",
            "--remove-orphans",
            "--abort-on-container-exit",
            "--quiet-pull",
        ])
        .current_dir(dir)
        .stdout(sink.stdio().map_err(ComposeError::exec(UP))?)
        .stderr(sink.stdio().map_err(ComposeError::exec(UP))?)
        .kill_on_drop(true)
        .spawn()
        .map_err(ComposeError::exec(UP))?;

    let Some(status) = token.run_until_cancelled(child.wait()).await else {
        let _ = child.kill().await;
        return Ok(UpOutcome::Cancelled);
    };
    let status = status.map_err(ComposeError::exec(UP))?;

    if status.success() {
        Ok(UpOutcome::Exited)
    } else if token.is_cancelled() {
        Ok(UpOutcome::Cancelled)
    } else {
        Err(ComposeError::exec(UP)(CommandError::Exit(status)))
    }
}

/// Builds the images and creates the containers without starting them:
/// `docker compose up --no-start --build`.
pub async fn build_and_create(dir: impl AsRef<Path>) -> Result<()> {
    info!("Executing docker compose up --no-start --build");

    let output = Command::new("docker")
        .args(["compose", "up", "--no-start", "--build"])
        .current_dir(dir.as_ref())
        .output()
        .await;

    CommandError::check_output(output)
        .map(drop)
        .map_err(ComposeError::exec(
            "exec docker compose up --no-start --build",
        ))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn log_sink_file_is_created_and_appended() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("compose.log");
        fs::write(&path, "existing\n").expect("seed log");

        let mut sink = LogSink::open(Some(&path)).expect("open sink");
        sink.banner("===== define step: docker compose up =====\n");
        sink.banner("===== lock step: docker compose up =====\n");
        drop(sink);

        let content = fs::read_to_string(&path).expect("read log");
        assert_eq!(
            content,
            "existing\n===== define step: docker compose up =====\n===== lock step: docker compose up =====\n"
        );
    }

    #[test]
    fn print_docker_compose_reports_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");

        let err = print_docker_compose(dir.path()).expect_err("missing compose file fails");
        assert!(
            matches!(
                &err,
                ComposeError::Io {
                    context: "read docker-compose.yml",
                    ..
                }
            ),
            "{err:?}"
        );
    }
}
