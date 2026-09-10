//! Docker-based smoke tests: each scenario stands up a full compose cluster
//! and watches it for alerts. All are ignored by default; run them with
//!
//! ```text
//! cargo test -p pluto-test-compose --test smoke -- --ignored --nocapture [--skip very_large]
//! ```
//!
//! Scenarios run one at a time whatever `--test-threads` says: clusters
//! competing for CPU and memory produce duty timeouts that a sequential run
//! never sees, so a concurrent pass would test the host, not the cluster.
//!
//! Environment:
//! - `PLUTO_REPO`: pluto checkout to build `pluto:local` from; scenarios that
//!   run pluto are skipped when it is unset.
//! - `SMOKE_SUDO_PERMS=1`: fix root-owned artefacts with `sudo` after each
//!   step.
//! - `SMOKE_LOG_DIR=<dir>`: write each scenario's `docker compose up` output to
//!   `<dir>/<scenario>.log` instead of stdout.
//! - `SMOKE_EXTERNAL_RELAY=<url>`: route the cluster through an external relay.

use std::path::PathBuf;

use pluto_test_compose::{PLUTO_REPO_ENV, auto, env_non_empty, smoke, write_config};
use tokio::sync::Mutex;

/// Held for the whole of a scenario so the docker clusters never overlap.
static SERIAL: Mutex<()> = Mutex::const_new(());

async fn run_scenario(name: &str) {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let scenario = smoke::scenario(name).unwrap_or_else(|| panic!("unknown scenario {name}"));
    if scenario.requires_pluto() && env_non_empty(PLUTO_REPO_ENV).is_none() {
        eprintln!("skipping {name}: {PLUTO_REPO_ENV} not set");
        return;
    }

    let _serial = SERIAL.lock().await;

    let dir = tempfile::Builder::new()
        .prefix("smoke-")
        .tempdir()
        .expect("compose tempdir");
    write_config(dir.path(), &scenario.config()).expect("write config");

    let mut conf = scenario.auto_config(dir.path());
    conf.sudo_perms = env_non_empty("SMOKE_SUDO_PERMS").is_some_and(|value| value != "0");
    conf.log_file = env_non_empty("SMOKE_LOG_DIR")
        .map(|log_dir| PathBuf::from(log_dir).join(format!("{name}.log")));

    // Display, not Debug, so the failure line carries the error message.
    if let Err(err) = auto(conf).await {
        panic!("smoke scenario {name} failed: {err}");
    }
}

macro_rules! smoke_tests {
    ($($test:ident => $name:literal),* $(,)?) => {
        const SCENARIO_NAMES: &[&str] = &[$($name),*];

        $(
            #[tokio::test]
            #[ignore = "docker-based smoke test; run with --ignored"]
            async fn $test() {
                run_scenario($name).await;
            }
        )*
    };
}

smoke_tests! {
    scenario_default_alpha => "default_alpha",
    scenario_default_beta => "default_beta",
    scenario_default_stable => "default_stable",
    scenario_dkg => "dkg",
    scenario_very_large => "very_large",
    scenario_1_of_4_down => "1_of_4_down",
    scenario_1_of_3_down => "1_of_3_down",
    scenario_blinded_blocks_vmock => "blinded_blocks_vmock",
    scenario_pluto_keygen_create => "pluto_keygen_create",
    scenario_all_pluto => "all_pluto",
    scenario_mixed_2_charon_2_pluto => "mixed_2_charon_2_pluto",
    scenario_pluto_dkg => "pluto_dkg",
}

#[test]
fn every_scenario_has_a_test() {
    let names: Vec<&str> = smoke::SCENARIOS.iter().map(|s| s.name).collect();
    assert_eq!(names, SCENARIO_NAMES);
}
