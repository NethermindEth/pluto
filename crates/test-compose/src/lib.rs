//! Docker-compose cluster generator for local and CI smoke testing of pluto
//! and charon nodes.
//!
//! A cluster is produced in steps. Each step reads `config.json` from the
//! compose directory, advances its `step` field and regenerates
//! `docker-compose.yml` from the bundled template:
//!
//! 1. [`new`] cleans the directory and writes a fresh config.
//! 2. [`define`] renders the cluster-definition step (`charon create dkg`, or a
//!    no-op container for `create` key generation), copies the static
//!    monitoring configs and writes the Prometheus scrape and alert-rule files.
//! 3. [`lock`] renders the cluster-lock step (`charon create cluster` or a full
//!    `charon dkg` run).
//! 4. [`run`] renders the compose file that runs the nodes, validator clients,
//!    relay and monitoring stack.
//!
//! [`auto`] chains the three steps against a docker daemon, brings the
//! cluster up and watches Prometheus for alerts while it runs; [`smoke`]
//! holds the scenario matrix the smoke tests feed into it.

mod alert;
mod auto;
mod config;
mod define;
mod duration;
mod error;
mod fsutil;
mod gotmpl;
mod lock;
mod new;
mod process;
mod run;
pub mod smoke;
mod static_files;
mod template;

#[cfg(test)]
mod golden_tests;

pub use alert::{
    ALERT_POLL_INTERVAL, ALERT_WARMUP, ALERTS_POLLED, ActiveAlert, AlertPoller, AlertTiming,
    DockerCurlPoller, PromAlert, PromAlertAnnotations, PromAlerts, PromAnnotations, PromData,
    PromGroup, PromRule, STARTUP_TRANSIENT_RULES, get_active_alerts, is_startup_transient,
    start_collector,
};
pub use auto::{AutoConfig, TmplFn, auto, run_step};
pub use config::{
    CHARON_PORTS, Config, KeyGen, NodeImpl, Step, VERSION, VcType, load_config, write_config,
};
pub use define::{
    ALERT_RULE_NAMES, BROADCAST_RULE, DefineOptions, ERROR_RATE_RULE, KeyGenError, KeyGenFn,
    PLUTO_DOWN_RULE, PROXY_RATE_RULE, VAPI_RATE_RULE, WARN_RATE_RULE, build_local,
    build_local_pluto, clean, define,
};
pub use duration::go_duration_string;
pub use error::{CommandError, ComposeError, Result};
pub use lock::lock;
pub use new::new;
pub use process::{
    LogSink, UpOutcome, build_and_create, down, fix_perms, print_docker_compose, up,
};
pub use run::run;
pub use template::{Kv, Port, TmplData, TmplNode, TmplVc, write_docker_compose};
