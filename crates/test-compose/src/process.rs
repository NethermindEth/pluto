//! Docker compose process control for the automated flow: bring clusters up
//! and down, build images, fix artefact permissions and print the compose file.
//!
//! Every command is resolved through `PATH` and run in the compose directory,
//! so the command sequence can be observed with stand-in programs (see the
//! transcript tests) as well as against a real docker daemon.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{ExitStatus, Stdio},
};

use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    define::combined_output,
    error::{CommandError, ComposeError, Result},
};

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
                .map_err(ComposeError::OpenLogFile),
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

fn exit_ok(status: ExitStatus) -> std::result::Result<(), CommandError> {
    if status.success() {
        Ok(())
    } else {
        Err(CommandError::Exit(status))
    }
}

/// Streams `docker-compose.yml` to stdout by running `cat` in `dir`.
pub async fn print_docker_compose(dir: impl AsRef<Path>) -> Result<()> {
    info!("Printing docker-compose.yml");

    let status = Command::new("cat")
        .arg("docker-compose.yml")
        .current_dir(dir.as_ref())
        .status()
        .await
        .map_err(|err| ComposeError::ExecCatDockerCompose(CommandError::Io(err)))?;

    exit_ok(status).map_err(ComposeError::ExecCatDockerCompose)
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
            .await
            .map_err(|err| ComposeError::ExecSudo {
                program: program.to_string(),
                source: CommandError::Io(err),
            })?;

        exit_ok(status).map_err(|source| ComposeError::ExecSudo {
            program: program.to_string(),
            source,
        })?;
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
        .await
        .map_err(|err| ComposeError::RunDown(CommandError::Io(err)))?;

    exit_ok(status).map_err(ComposeError::RunDown)
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

    let output = tokio::select! {
        output = build.output() => output.map_err(|err| ComposeError::ExecComposeBuild {
            source: CommandError::Io(err),
            output: String::new(),
        })?,
        () = token.cancelled() => {
            return Err(ComposeError::ExecComposeBuild {
                source: CommandError::Io(io::Error::other("signal: killed")),
                output: String::new(),
            });
        }
    };
    if !output.status.success() {
        return Err(ComposeError::ExecComposeBuild {
            source: CommandError::Exit(output.status),
            output: combined_output(&output),
        });
    }

    info!("Executing docker compose up");

    let stdout = sink
        .stdio()
        .map_err(|err| ComposeError::ExecComposeUp(CommandError::Io(err)))?;
    let stderr = sink
        .stdio()
        .map_err(|err| ComposeError::ExecComposeUp(CommandError::Io(err)))?;
    let mut child = Command::new("docker")
        .args([
            "compose",
            "up",
            "--remove-orphans",
            "--abort-on-container-exit",
            "--quiet-pull",
        ])
        .current_dir(dir)
        .stdout(stdout)
        .stderr(stderr)
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| ComposeError::ExecComposeUp(CommandError::Io(err)))?;

    let status = tokio::select! {
        status = child.wait() => {
            status.map_err(|err| ComposeError::ExecComposeUp(CommandError::Io(err)))?
        }
        () = token.cancelled() => {
            let _ = child.kill().await;
            return Ok(UpOutcome::Cancelled);
        }
    };

    if status.success() {
        Ok(UpOutcome::Exited)
    } else if token.is_cancelled() {
        Ok(UpOutcome::Cancelled)
    } else {
        Err(ComposeError::ExecComposeUp(CommandError::Exit(status)))
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
        .await
        .map_err(|err| ComposeError::ExecComposeCreate {
            source: CommandError::Io(err),
            output: String::new(),
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(ComposeError::ExecComposeCreate {
            source: CommandError::Exit(output.status),
            output: combined_output(&output),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

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
    fn log_sink_creates_file_with_0644() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("new.log");

        let sink = LogSink::open(Some(&path)).expect("open sink");
        drop(sink);

        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn log_sink_open_missing_parent_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing").join("compose.log");

        let err = LogSink::open(Some(&path)).expect_err("open must fail");
        assert!(matches!(err, ComposeError::OpenLogFile(_)), "{err:?}");
        assert!(err.to_string().starts_with("open log file: "), "{err}");
    }

    #[test]
    fn log_sink_stdout_never_fails() {
        let mut sink = LogSink::open(None).expect("stdout sink");
        assert!(matches!(sink, LogSink::Stdout));
        sink.banner("");
    }

    #[tokio::test]
    async fn print_docker_compose_runs_cat_in_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("docker-compose.yml"), "services: {}\n").expect("write yml");

        print_docker_compose(dir.path())
            .await
            .expect("cat of an existing file succeeds");
    }

    #[tokio::test]
    async fn print_docker_compose_reports_cat_failure() {
        let dir = tempfile::tempdir().expect("tempdir");

        let err = print_docker_compose(dir.path())
            .await
            .expect_err("cat of a missing file fails");
        assert_eq!(
            err.to_string(),
            "exec cat docker-compose.yml: exit status: 1"
        );
    }
}
