//! Private key locking service.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

/// Duration after which a private key lock file is considered stale.
const STALE_DURATION: Duration = Duration::from_secs(5);

/// Duration after which the private key lock file is updated.
const UPDATE_PERIOD: Duration = Duration::from_secs(1);

/// Error type for private key lock operations.
#[derive(Debug, thiserror::Error)]
pub enum PrivKeyLockError {
    /// Cannot read the private key lock file.
    #[error("cannot read private key lock file: path={path}")]
    ReadFile {
        /// The underlying I/O error.
        source: std::io::Error,
        /// Path to the lock file.
        path: PathBuf,
    },

    /// Cannot decode the private key lock file content.
    #[error("cannot decode private key lock file content: path={path}")]
    DecodeFile {
        /// The underlying JSON error.
        source: serde_json::Error,
        /// Path to the lock file.
        path: PathBuf,
    },

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

    /// Cannot marshal the private key lock file.
    #[error("cannot marshal private key lock file")]
    MarshalFile(#[from] serde_json::Error),

    /// Cannot write the private key lock file.
    #[error("cannot write private key lock file: path={path}")]
    WriteFile {
        /// The underlying I/O error.
        source: std::io::Error,
        /// Path to the lock file.
        path: PathBuf,
    },

    /// Cannot delete the private key lock file.
    #[error("deleting private key lock file failed")]
    DeleteFile(#[source] std::io::Error),
}

type Result<T> = std::result::Result<T, PrivKeyLockError>;

/// Metadata stored in the lock file.
#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    command: String,
    timestamp: DateTime<Utc>,
}

/// Creates or updates the lock file with the latest metadata.
async fn write_file(path: &Path, command: &str, now: DateTime<Utc>) -> Result<()> {
    let meta = Metadata {
        command: command.to_owned(),
        timestamp: now,
    };

    let bytes = serde_json::to_vec(&meta)?;

    tokio::fs::write(path, bytes)
        .await
        .map_err(|source| PrivKeyLockError::WriteFile {
            source,
            path: path.to_path_buf(),
        })
}

/// Private key locking service.
#[derive(Debug)]
pub struct Service {
    command: String,
    path: PathBuf,
    update_period: Duration,
    quit: CancellationToken,
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
                return Err(PrivKeyLockError::ReadFile {
                    source: e,
                    path: path.clone(),
                });
            }
            Ok(content) => {
                let meta: Metadata = serde_json::from_slice(&content).map_err(|source| {
                    PrivKeyLockError::DecodeFile {
                        source,
                        path: path.clone(),
                    }
                })?;

                let elapsed = Utc::now().signed_duration_since(meta.timestamp);
                let stale = chrono::Duration::from_std(STALE_DURATION)
                    .expect("STALE_DURATION fits in chrono::Duration");

                if elapsed <= stale {
                    return Err(PrivKeyLockError::ActiveLock {
                        path: path.clone(),
                        command: meta.command,
                    });
                }
            }
        }

        write_file(&path, &command, Utc::now()).await?;

        Ok(Self {
            command,
            path,
            update_period: UPDATE_PERIOD,
            quit: CancellationToken::new(),
        })
    }

    /// Runs the service, updating the lock file periodically and deleting it on
    /// cancellation.
    pub async fn run(&self) -> Result<()> {
        let mut interval = tokio::time::interval(self.update_period);
        // Consume the first immediate tick.
        interval.tick().await;

        loop {
            tokio::select! {
                () = self.quit.cancelled() => {
                    tokio::fs::remove_file(&self.path)
                        .await
                        .map_err(PrivKeyLockError::DeleteFile)?;

                    return Ok(());
                }
                _ = interval.tick() => {
                    write_file(&self.path, &self.command, Utc::now()).await?;
                }
            }
        }
    }

    /// Signals the service to stop.
    ///
    /// The caller should await the [`run`](Self::run) future/task to observe
    /// completion.
    pub fn close(&self) {
        self.quit.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    #[tokio::test]
    async fn test_service() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path: PathBuf = dir.path().join("privkeylocktest");

        // Create a stale file that is ignored.
        let stale_time =
            Utc::now() - chrono::Duration::from_std(STALE_DURATION).expect("duration fits");
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
            let svc_path = svc.path.clone();
            let svc_command = svc.command.clone();
            let svc_update_period = svc.update_period;
            async move {
                let svc = Service {
                    command: svc_command,
                    path: svc_path,
                    update_period: svc_update_period,
                    quit: svc_quit,
                };
                svc.run().await
            }
        });

        assert_file_exists(&path).await;
        svc.close();

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
