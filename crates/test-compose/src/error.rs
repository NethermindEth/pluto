use std::{
    io,
    process::{ExitStatus, Output},
};

use pluto_eth2util::enr::RecordError;
use pluto_k1util::K1UtilError;

use crate::config::{NodeImpl, Step};

/// Failure of a child process such as `docker` or `git`.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("{0}")]
    Exit(ExitStatus),

    #[error("{status}: output={output}")]
    ExitOutput { status: ExitStatus, output: String },
}

impl CommandError {
    /// Turns the result of waiting for a command into an error unless it
    /// exited successfully.
    pub fn check(status: io::Result<ExitStatus>) -> std::result::Result<(), Self> {
        let status = status?;
        if status.success() {
            Ok(())
        } else {
            Err(Self::Exit(status))
        }
    }

    /// Returns the captured output of a command that exited successfully; on
    /// failure the combined stdout and stderr travel with the error.
    pub fn check_output(output: io::Result<Output>) -> std::result::Result<Output, Self> {
        let output = output?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(Self::ExitOutput {
                status: output.status,
                output: combined_output(&output),
            })
        }
    }
}

/// Joins captured stdout and stderr, lossily decoded.
pub(crate) fn combined_output(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

/// Errors returned by the compose generator.
#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    #[error("compose config not new, so can't be defined: step={step}")]
    NotNew { step: Step },

    #[error("compose config not defined, so can't be locked: step={step}")]
    NotDefined { step: Step },

    #[error("compose config not locked, so can't be run: step={step}")]
    NotLocked { step: Step },

    #[error("save charon-enr-private-key: {0}")]
    SaveEnrPrivateKey(#[from] K1UtilError),

    #[error(transparent)]
    Enr(#[from] RecordError),

    #[error("split-keys-dir must be a child of compose dir: relative={relative}")]
    SplitKeysDirNotChild { relative: String },

    #[error("relative split keys dir: Rel: can't make {target} relative to {base}")]
    RelativeSplitKeysDir { base: String, target: String },

    #[error(
        "cannot build local {node_impl} binary; {var} env var, the path to the {node_impl} repo, is not set"
    )]
    RepoNotSet {
        node_impl: NodeImpl,
        var: &'static str,
    },

    /// A file system operation named by `context` failed.
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },

    /// A child process named by `cmd` could not be run or failed.
    #[error("{cmd}: {source}")]
    Exec {
        cmd: String,
        #[source]
        source: CommandError,
    },

    #[error("unknown alert rule name in alert_disable_rules: rule={rule}")]
    UnknownAlertRule { rule: String },

    #[error("marshal config: {0}")]
    MarshalConfig(#[source] serde_json::Error),

    #[error("unmarshal Config: {0}")]
    UnmarshalConfig(#[source] serde_json::Error),

    #[error("no validator clients configured")]
    NoValidatorClients,

    #[error("external port overflow: node={index}")]
    PortOverflow { index: usize },

    #[error("cluster stopped before the observation window elapsed")]
    ClusterStopped,

    #[error("prometheus was not polled successfully through the end of the observation window")]
    PrometheusNotPolled,

    #[error("alerts detected: alerts=[{}]", .alerts.join(" "))]
    AlertsDetected { alerts: Vec<String> },

    #[error("unmarshal alerts: {source}: out={out}")]
    UnmarshalAlerts {
        #[source]
        source: serde_json::Error,
        out: String,
    },

    #[error("run step: {0}")]
    StepCancelled(#[source] tokio::task::JoinError),
}

impl ComposeError {
    /// Wraps an I/O error with the operation it came from.
    pub(crate) fn io(context: &'static str) -> impl FnOnce(io::Error) -> Self {
        move |source| Self::Io { context, source }
    }

    /// Wraps a command failure with the command it came from.
    pub(crate) fn exec<E: Into<CommandError>>(cmd: impl Into<String>) -> impl FnOnce(E) -> Self {
        let cmd = cmd.into();
        move |source| Self::Exec {
            cmd,
            source: source.into(),
        }
    }
}

/// Result alias for compose operations.
pub type Result<T> = std::result::Result<T, ComposeError>;
