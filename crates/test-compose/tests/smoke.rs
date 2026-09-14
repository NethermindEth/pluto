//! Docker-based smoke tests: each scenario stands up a full compose cluster
//! and watches it for alerts. Feature-gated behind `smoke` (see the crate
//! README for the run command and environment variables), so a plain `cargo
//! test --workspace` never builds or runs them.
//!
//! Scenarios run one at a time whatever `--test-threads` says: clusters
//! competing for CPU and memory produce duty timeouts a sequential run never
//! sees.

use std::path::PathBuf;

use pluto_test_compose::{PLUTO_REPO_ENV, auto, env_non_empty, smoke, write_config};
use tokio::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::const_new(());

#[test_case::test_case("default_alpha" ; "default_alpha")]
#[test_case::test_case("default_beta" ; "default_beta")]
#[test_case::test_case("default_stable" ; "default_stable")]
#[test_case::test_case("dkg" ; "dkg")]
#[test_case::test_case("very_large" ; "very_large")]
#[test_case::test_case("node_1_of_4_down" ; "node_1_of_4_down")]
#[test_case::test_case("node_1_of_3_down" ; "node_1_of_3_down")]
#[test_case::test_case("blinded_blocks_vmock" ; "blinded_blocks_vmock")]
#[test_case::test_case("pluto_keygen_create" ; "pluto_keygen_create")]
#[test_case::test_case("all_pluto" ; "all_pluto")]
#[test_case::test_case("mixed_2_charon_2_pluto" ; "mixed_2_charon_2_pluto")]
#[test_case::test_case("pluto_dkg" ; "pluto_dkg")]
#[tokio::test]
async fn scenario(name: &str) {
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

/// One `test_case` line per `smoke::SCENARIOS` entry. Catches the matrix and
/// the test cases drifting apart (an entry added to one but not the other)
/// without listing every name a second time; a typo in a case's first
/// argument instead fails at runtime via `scenario`'s `unwrap_or_else`.
#[test]
fn scenario_count_matches_matrix() {
    const CASES: usize = 12;
    assert_eq!(smoke::SCENARIOS.len(), CASES);
}
