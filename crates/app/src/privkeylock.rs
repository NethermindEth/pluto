//! Private key locking service.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

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

/// Metadata stored in the lock file.
#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    command: String,
    timestamp: DateTime<Utc>,
}

/// Reports whether a lock file written at `timestamp` is stale at `now`.
fn is_stale(timestamp: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now.signed_duration_since(timestamp)
        .to_std()
        .is_ok_and(|elapsed| elapsed > STALE_DURATION)
}

/// Creates or updates the lock file with the latest metadata.
async fn write_file(path: &Path, command: &str, now: DateTime<Utc>) -> Result<()> {
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

                if !is_stale(meta.timestamp, Utc::now()) {
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
                    write_file(&self.path, &self.command, Utc::now()).await?;
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

    use chrono::{FixedOffset, SecondsFormat, TimeDelta};
    use std::path::PathBuf;

    /// A lock file exactly as charon writes it.
    const CHARON_LOCK_FILE: &str =
        r#"{"command":"charon run","timestamp":"2026-08-12T10:15:30.123456789Z"}"#;

    /// The charon lock file re-stamped with `now`, so it reads as a live lock.
    ///
    /// Stamped in a zone two hours behind UTC, as charon does outside UTC.
    /// Ignoring the offset would backdate the lock past [`STALE_DURATION`].
    fn charon_lock_file_at(now: DateTime<Utc>) -> String {
        let zone = FixedOffset::west_opt(7_200).expect("valid offset");

        format!(
            r#"{{"command":"charon run","timestamp":"{}"}}"#,
            now.with_timezone(&zone)
                .to_rfc3339_opts(SecondsFormat::Nanos, false)
        )
    }

    /// Returns a timestamp aged [`STALE_DURATION`] plus `offset_ms` at `now`.
    fn aged_around_threshold(now: DateTime<Utc>, offset_ms: i64) -> DateTime<Utc> {
        let stale_ms =
            i64::try_from(STALE_DURATION.as_millis()).expect("stale duration in i64 range");
        let age = TimeDelta::milliseconds(stale_ms.checked_add(offset_ms).expect("age in range"));

        now.checked_sub_signed(age).expect("timestamp in range")
    }

    #[test]
    fn round_trips_the_charon_wire_format() {
        let meta: Metadata =
            serde_json::from_str(CHARON_LOCK_FILE).expect("decode charon lock file");

        let bytes = serde_json::to_vec(&meta).expect("encode metadata");

        // Byte-identical to what charon wrote.
        assert_eq!(
            String::from_utf8(bytes).expect("metadata is utf8"),
            CHARON_LOCK_FILE
        );
    }

    #[tokio::test]
    async fn charon_lock_file_reports_another_instance_running() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path: PathBuf = dir.path().join("privkeylocktest");

        tokio::fs::write(&path, charon_lock_file_at(Utc::now()))
            .await
            .expect("write charon lock file");

        let err = Service::new(&path, "test")
            .await
            .expect_err("charon lock file should be active");

        match err {
            PrivKeyLockError::ActiveLock { command, .. } => assert_eq!(command, "charon run"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn staleness_boundary_is_sub_second() {
        let now = Utc::now();

        assert!(!is_stale(aged_around_threshold(now, -1), now));
        assert!(!is_stale(aged_around_threshold(now, 0), now));
        assert!(is_stale(aged_around_threshold(now, 1), now));

        let future = now
            .checked_add_signed(TimeDelta::seconds(60))
            .expect("timestamp in range");
        assert!(!is_stale(future, now));
    }

    #[tokio::test]
    async fn service() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path: PathBuf = dir.path().join("privkeylocktest");

        // Create a stale file that is ignored (one extra second past the
        // threshold).
        let stale_time = aged_around_threshold(Utc::now(), 1_000);
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
