//! Private key locking service.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

/// Duration after which a private key lock file is considered stale.
const STALE_DURATION: Duration = Duration::from_secs(5);

/// Duration after which the private key lock file is updated.
const UPDATE_PERIOD: Duration = Duration::from_secs(1);

/// Error type for private key lock operations.
#[derive(Debug, thiserror::Error)]
pub enum PrivKeyLockError {
    /// I/O error on the private key lock file.
    #[error("private key lock file I/O error {0}")]
    Io(#[from] std::io::Error),

    /// JSON error on the private key lock file.
    #[error("private key lock file JSON error {0}")]
    Json(#[from] serde_json::Error),

    /// Another charon instance may be running.
    #[error(
        "existing private key lock file found, another charon instance may be running on your machine: path={path}, command={command}"
    )]
    ActiveLock {
        /// Path to the lock file.
        path: PathBuf,
        /// Command stored in the lock file.
        command: String,
    },
}

type Result<T> = std::result::Result<T, PrivKeyLockError>;

/// Returns the current unix timestamp in seconds.
fn now_secs() -> u64 {
    #[allow(clippy::unwrap_used, reason = "system clock must be after unix epoch")]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after unix epoch")
        .as_secs()
}

/// Metadata stored in the lock file.
#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    command: String,
    timestamp: u64,
}

/// Creates or updates the lock file with the latest metadata.
async fn write_file(path: &Path, command: &str, now: u64) -> Result<()> {
    let meta = Metadata {
        command: command.to_owned(),
        timestamp: now,
    };

    let bytes = serde_json::to_vec(&meta)?;

    tokio::fs::write(path, bytes).await.map_err(Into::into)
}

/// Private key locking service.
#[derive(Debug)]
pub struct Service {
    command: String,
    path: PathBuf,
    update_period: Duration,
    quit: CancellationToken,
    done: CancellationToken,
}

impl Service {
    /// Returns a new private key locking service.
    ///
    /// Errors if a recently-updated private key lock file exists.
    pub async fn new(path: impl AsRef<Path>, command: impl AsRef<str>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let command = command.as_ref().to_owned();

        match tokio::fs::read(&path).await {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No file, we will create it in run.
            }
            Err(e) => {
                return Err(e.into());
            }
            Ok(content) => {
                let meta: Metadata = serde_json::from_slice(&content)?;

                let elapsed = now_secs().saturating_sub(meta.timestamp);

                if elapsed <= STALE_DURATION.as_secs() {
                    return Err(PrivKeyLockError::ActiveLock {
                        path: path.clone(),
                        command: meta.command,
                    });
                }
            }
        }

        write_file(&path, &command, now_secs()).await?;

        Ok(Self {
            command,
            path,
            update_period: UPDATE_PERIOD,
            quit: CancellationToken::new(),
            done: CancellationToken::new(),
        })
    }

    /// Runs the service, updating the lock file periodically and deleting it on
    /// cancellation.
    pub async fn run(&self) -> Result<()> {
        let _done_guard = self.done.clone().drop_guard();

        let mut interval = tokio::time::interval(self.update_period);
        interval.tick().await;

        loop {
            tokio::select! {
                () = self.quit.cancelled() => {
                    match tokio::fs::remove_file(&self.path).await {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }

                    return Ok(());
                }
                _ = interval.tick() => {
                    write_file(&self.path, &self.command, now_secs()).await?;
                }
            }
        }
    }

    /// Closes the service, waiting for [`run`](Self::run) to finish.
    ///
    /// Note: this will wait forever if `run` was never called.
    pub async fn close(&self) {
        self.quit.cancel();
        self.done.cancelled().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    #[tokio::test]
    async fn service() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path: PathBuf = dir.path().join("privkeylocktest");

        // Create a stale file that is ignored (one extra second past the threshold).
        let stale_time = now_secs()
            .saturating_sub(STALE_DURATION.as_secs())
            .saturating_sub(1);
        write_file(&path, "test", stale_time)
            .await
            .expect("write stale file");

        // Create a new service.
        let svc = Service::new(path.clone(), "test")
            .await
            .expect("create service");
        // Speed up the update period for testing.
        let svc = Service {
            update_period: Duration::from_millis(1),
            ..svc
        };

        assert_file_exists(&path).await;

        // Assert a new service can't be created.
        let err = Service::new(path.clone(), "test")
            .await
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("existing private key lock file found"),
            "unexpected error: {msg}"
        );

        // Delete the file so Run will create it again.
        tokio::fs::remove_file(&path)
            .await
            .expect("remove lock file");

        let run_handle = tokio::spawn({
            let svc_quit = svc.quit.clone();
            let svc_done = svc.done.clone();
            let svc_path = svc.path.clone();
            let svc_command = svc.command.clone();
            let svc_update_period = svc.update_period;
            async move {
                let svc = Service {
                    command: svc_command,
                    path: svc_path,
                    update_period: svc_update_period,
                    quit: svc_quit,
                    done: svc_done,
                };
                svc.run().await
            }
        });

        assert_file_exists(&path).await;
        svc.close().await;

        run_handle
            .await
            .expect("join run task")
            .expect("run should succeed");

        // Assert the file is deleted.
        let result = tokio::fs::metadata(&path).await;
        assert!(result.is_err(), "file should be deleted");
    }

    async fn assert_file_exists(path: &Path) {
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_secs(1))
            .expect("deadline overflow");
        loop {
            if tokio::fs::metadata(path).await.is_ok() {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("file did not appear within timeout: {}", path.display());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}
