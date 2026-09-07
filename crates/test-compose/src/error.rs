use std::{io, process::ExitStatus};

use pluto_eth2util::enr::RecordError;
use pluto_k1util::K1UtilError;

use crate::{config::Step, gotmpl};

/// Failure of a child process such as `docker` or `git`.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    /// The process could not be spawned or waited on.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// The process ran but exited unsuccessfully.
    #[error("{0}")]
    Exit(ExitStatus),
}

/// Errors returned by the compose generator.
#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    /// The directory holds Go sources, so it is not a compose directory.
    #[error("go files found, compose dir incorrect: dir={dir}")]
    GoFilesFound {
        /// The directory that was about to be cleaned.
        dir: String,
    },

    /// Deleting a compose artefact failed.
    #[error("remove file: {0}")]
    RemoveFile(#[source] io::Error),

    /// `define` requires a config at the `new` step.
    #[error("compose config not new, so can't be defined: step={step}")]
    NotNew {
        /// The step the config is actually at.
        step: Step,
    },

    /// `lock` requires a config at the `defined` step.
    #[error("compose config not defined, so can't be locked: step={step}")]
    NotDefined {
        /// The step the config is actually at.
        step: Step,
    },

    /// `run` requires a config at the `locked` step.
    #[error("compose config not locked, so can't be run: step={step}")]
    NotLocked {
        /// The step the config is actually at.
        step: Step,
    },

    /// The configured key generator failed to produce a p2p key.
    #[error("new key: {0}")]
    NewKey(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Writing a node's ENR private key failed.
    #[error("save charon-enr-private-key: {0}")]
    SaveEnrPrivateKey(#[source] K1UtilError),

    /// Building a node's ENR failed.
    #[error(transparent)]
    Enr(#[from] RecordError),

    /// The split keys directory is outside the compose directory.
    #[error("split-keys-dir must be a child of compose dir: relative={relative}")]
    SplitKeysDirNotChild {
        /// The split keys directory relative to the compose directory.
        relative: String,
    },

    /// Resolving a directory to an absolute path failed.
    #[error("abs dir: {0}")]
    AbsDir(#[source] io::Error),

    /// The split keys directory cannot be expressed relative to the compose
    /// directory.
    #[error("relative split keys dir: Rel: can't make {target} relative to {base}")]
    RelativeSplitKeysDir {
        /// The absolute compose directory.
        base: String,
        /// The absolute split keys directory.
        target: String,
    },

    /// `docker pull` failed.
    #[error("run docker pull: {0}")]
    RunDockerPull(#[source] CommandError),

    /// A local charon build was requested without `CHARON_REPO`.
    #[error(
        "cannot build local charon binary; CHARON_REPO env var, the path to the charon repo, is not set"
    )]
    CharonRepoNotSet,

    /// A local pluto build was requested without `PLUTO_REPO`.
    #[error(
        "cannot build local pluto binary; PLUTO_REPO env var, the path to the pluto repo, is not set"
    )]
    PlutoRepoNotSet,

    /// `docker build` failed.
    #[error("exec docker build: {source}: output={output}")]
    ExecDockerBuild {
        /// The process failure.
        #[source]
        source: CommandError,
        /// Combined stdout and stderr of the build.
        output: String,
    },

    /// `git rev-parse` failed.
    #[error("git rev-parse: {0}")]
    GitRevParse(#[source] CommandError),

    /// Creating a static config directory failed.
    #[error("mkdir all: {0}")]
    MkdirAll(#[source] io::Error),

    /// Writing a static config file failed.
    #[error("write file: {0}")]
    WriteFile(#[source] io::Error),

    /// Creating the prometheus directory failed.
    #[error("mkdir prometheus: {0}")]
    MkdirPrometheus(#[source] io::Error),

    /// Writing the prometheus scrape config failed.
    #[error("write prometheus.yml: {0}")]
    WritePrometheusYml(#[source] io::Error),

    /// Writing the prometheus alert rules failed.
    #[error("write rules.yml: {0}")]
    WriteRulesYml(#[source] io::Error),

    /// `alert_disable_rules` names a rule that does not exist.
    #[error("unknown alert rule name in alert_disable_rules: rule={rule}")]
    UnknownAlertRule {
        /// The unknown rule name.
        rule: String,
    },

    /// Serialising the config failed.
    #[error("marshal config: {0}")]
    MarshalConfig(#[source] serde_json::Error),

    /// Writing `config.json` failed.
    #[error("write config: {0}")]
    WriteConfig(#[source] io::Error),

    /// Reading `config.json` failed.
    #[error("load config: {0}")]
    LoadConfig(#[source] io::Error),

    /// Parsing `config.json` failed.
    #[error("unmarshal Config: {0}")]
    UnmarshalConfig(#[source] serde_json::Error),

    /// `run` needs at least one validator client type to cycle through.
    #[error("no validator clients configured")]
    NoValidatorClients,

    /// A node's external port offset does not fit the port type.
    #[error("external port overflow: node={index}")]
    PortOverflow {
        /// The node index whose ports overflowed.
        index: usize,
    },

    /// Rendering the teku command template failed.
    #[error("teku template: {0}")]
    TekuTemplate(#[source] gotmpl::Error),

    /// Parsing the docker-compose template failed.
    #[error("new template: {0}")]
    NewTemplate(#[source] gotmpl::Error),

    /// Rendering the docker-compose template failed.
    #[error("exec template: {0}")]
    ExecTemplate(#[source] gotmpl::Error),

    /// Writing `docker-compose.yml` failed.
    #[error("write docker-compose.yml: {0}")]
    WriteDockerCompose(#[source] io::Error),

    /// Opening the `docker compose up` log file failed.
    #[error("open log file: {0}")]
    OpenLogFile(#[source] io::Error),

    /// Printing `docker-compose.yml` with `cat` failed.
    #[error("exec cat docker-compose.yml: {0}")]
    ExecCatDockerCompose(#[source] CommandError),

    /// A `sudo` command fixing artefact permissions failed.
    #[error("exec sudo {program}: {source}")]
    ExecSudo {
        /// The program run under sudo (`chown` or `chmod`).
        program: String,
        /// The process failure.
        #[source]
        source: CommandError,
    },

    /// `docker compose down` failed.
    #[error("run down: {0}")]
    RunDown(#[source] CommandError),

    /// `docker compose build` failed.
    #[error("exec docker compose build: {source}: output={output}")]
    ExecComposeBuild {
        /// The process failure.
        #[source]
        source: CommandError,
        /// Combined stdout and stderr of the build.
        output: String,
    },

    /// `docker compose up` failed.
    #[error("exec docker compose up: {0}")]
    ExecComposeUp(#[source] CommandError),

    /// `docker compose up --no-start --build` failed.
    #[error("exec docker compose up --no-start --build: {source}: output={output}")]
    ExecComposeCreate {
        /// The process failure.
        #[source]
        source: CommandError,
        /// Combined stdout and stderr of the command.
        output: String,
    },

    /// The cluster exited before the alert observation window elapsed.
    #[error("cluster stopped before the observation window elapsed")]
    ClusterStopped,

    /// Prometheus polling was not still healthy when the window closed.
    #[error("prometheus was not polled successfully through the end of the observation window")]
    PrometheusNotPolled,

    /// Alerts fired while the cluster was observed.
    #[error("alerts detected: alerts=[{}]", .alerts.join(" "))]
    AlertsDetected {
        /// Descriptions of the firing alerts, in the order they were detected.
        alerts: Vec<String>,
    },

    /// The compose directory holds no `config.json`.
    #[error("compose config.json not found; write one with WriteConfig or New first: dir={dir}")]
    ConfigNotFound {
        /// The compose directory.
        dir: String,
    },

    /// Querying the Prometheus rules API through the `curl` container failed.
    #[error("exec curl alerts: {source}: out={out}")]
    ExecCurlAlerts {
        /// The process failure.
        #[source]
        source: CommandError,
        /// Combined stdout and stderr of the query.
        out: String,
    },

    /// Parsing the Prometheus rules API response failed.
    #[error("unmarshal alerts: {source}: out={out}")]
    UnmarshalAlerts {
        /// The parse failure.
        #[source]
        source: serde_json::Error,
        /// The response that failed to parse.
        out: String,
    },

    /// The blocking generator step was cancelled before it completed.
    #[error("run step: {0}")]
    StepCancelled(#[source] tokio::task::JoinError),
}

/// Result alias for compose operations.
pub type Result<T> = std::result::Result<T, ComposeError>;
