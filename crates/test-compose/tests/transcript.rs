//! Command-transcript parity with the Go harness, without docker.
//!
//! Each test re-executes this test binary to run one smoke scenario through
//! [`pluto_test_compose::auto`] with stand-in `docker`, `sudo`, `git` and `cat`
//! programs first on `PATH`. The stand-ins log every invocation; the log is
//! normalised and compared with `testdata/smoke/<scenario>.transcript`, which
//! was captured from `go test ./smoke -integration -sudo-perms` running the
//! same scenario through the same stand-ins.
//!
//! The re-exec exists because `PATH` is per process and the tests run in
//! parallel threads. Set `PLUTO_COMPOSE_TRANSCRIPT_OUT=<dir>` to also dump the
//! normalised transcripts for inspection.

use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use pluto_test_compose::{AlertTiming, auto, smoke, write_config};

const SHIM: &str = include_str!("../testdata/smoke/shim.sh");
const SHIM_PROGRAMS: [&str; 4] = ["docker", "sudo", "git", "cat"];
const GOLDEN_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/smoke");
const SCENARIO_ENV: &str = "TRANSCRIPT_SCENARIO";
const DIR_ENV: &str = "TRANSCRIPT_DIR";
const POLL_PREFIX: &str =
    "docker compose exec -T curl curl -s http://prometheus:9090/api/v1/rules?type=alert";

fn install_shims(bin: &Path) {
    for program in SHIM_PROGRAMS {
        let path = bin.join(program);
        fs::write(&path, SHIM).expect("write shim");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod shim");
    }
}

/// Replaces the numeric owner of `sudo chown -R <uid>:<gid> .` with a
/// placeholder, so the transcript does not depend on who runs the test.
fn normalize_owner(cmd: &str) -> String {
    let Some(rest) = cmd.strip_prefix("sudo chown -R ") else {
        return cmd.to_string();
    };
    let Some((owner, tail)) = rest.split_once(' ') else {
        return cmd.to_string();
    };
    let numeric = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    match owner.split_once(':') {
        Some((uid, gid)) if numeric(uid) && numeric(gid) => {
            format!("sudo chown -R <uid>:<gid> {tail}")
        }
        _ => cmd.to_string(),
    }
}

/// Normalises a raw shim log: working directories become `<repo>` or `<dir>`,
/// the chown owner becomes a placeholder, and the alert polls (whose count
/// depends on timing) collapse into a trailing `polls=yes|no` line.
fn normalize(raw: &str, repo: &Path) -> String {
    let mut repo_paths = vec![repo.to_string_lossy().into_owned()];
    if let Ok(canonical) = fs::canonicalize(repo) {
        repo_paths.push(canonical.to_string_lossy().into_owned());
    }

    let mut out = String::new();
    let mut polled = false;
    for line in raw.lines() {
        let (cmd, cwd) = line.split_once('\t').unwrap_or((line, ""));
        if cmd.starts_with(POLL_PREFIX) {
            polled = true;
            continue;
        }

        let cwd = if repo_paths.iter().any(|p| p == cwd) {
            "<repo>"
        } else {
            "<dir>"
        };
        out.push_str(&normalize_owner(cmd));
        out.push('\t');
        out.push_str(cwd);
        out.push('\n');
    }

    out.push_str(if polled { "polls=yes\n" } else { "polls=no\n" });

    out
}

fn assert_transcript(name: &str) {
    let root = tempfile::Builder::new()
        .prefix("transcript-")
        .tempdir()
        .expect("tempdir");
    let bin = root.path().join("bin");
    let repo = root.path().join("repo");
    let compose = root.path().join("compose");
    for dir in [&bin, &repo, &compose] {
        fs::create_dir(dir).expect("create dir");
    }
    install_shims(&bin);

    let path = env::join_paths(
        std::iter::once(bin.clone())
            .chain(env::split_paths(&env::var_os("PATH").unwrap_or_default())),
    )
    .expect("join PATH");
    let output = Command::new(env::current_exe().expect("current exe"))
        .args(["transcript_child", "--exact", "--ignored", "--nocapture"])
        .env("PATH", path)
        .env(SCENARIO_ENV, name)
        .env(DIR_ENV, &compose)
        .env(smoke::PLUTO_REPO_ENV, &repo)
        .env_remove(smoke::EXTERNAL_RELAY_ENV)
        .output()
        .expect("run transcript child");
    assert!(
        output.status.success(),
        "{name}: transcript child failed: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let raw = fs::read_to_string(root.path().join("transcript.log")).expect("read transcript");
    let actual = normalize(&raw, &repo);

    if let Some(out_dir) = env::var_os("PLUTO_COMPOSE_TRANSCRIPT_OUT") {
        let out_dir = PathBuf::from(out_dir);
        fs::create_dir_all(&out_dir).expect("create transcript out dir");
        fs::write(out_dir.join(format!("{name}.transcript")), &actual).expect("dump transcript");
    }

    let golden = Path::new(GOLDEN_DIR).join(format!("{name}.transcript"));
    let expected = fs::read_to_string(&golden)
        .unwrap_or_else(|err| panic!("read golden {}: {err}", golden.display()));
    assert_eq!(
        actual, expected,
        "{name}: command transcript differs from the Go harness"
    );
}

/// The re-executed half: runs one scenario with a short alert window against
/// the shims. A no-op unless the parent set the scenario, so a plain
/// `cargo test -- --ignored` does not trip over it.
#[tokio::test]
#[ignore = "helper re-executed by the transcript tests"]
async fn transcript_child() {
    let Some(name) = env::var_os(SCENARIO_ENV) else {
        return;
    };
    let name = name.to_string_lossy().into_owned();
    let dir = PathBuf::from(env::var_os(DIR_ENV).expect("TRANSCRIPT_DIR is set"));
    let scenario = smoke::scenario(&name).unwrap_or_else(|| panic!("unknown scenario {name}"));

    write_config(&dir, &scenario.config()).expect("write config");

    let mut conf = scenario.auto_config(&dir);
    conf.alert_timeout = Duration::from_secs(3);
    conf.sudo_perms = true;
    conf.timing = AlertTiming {
        warmup: Duration::from_secs(1),
        poll_interval: Duration::from_millis(100),
    };

    auto(conf).await.expect("auto run against the shims");
}

macro_rules! transcript_tests {
    ($($test:ident => $name:literal),* $(,)?) => {
        const SCENARIO_NAMES: &[&str] = &[$($name),*];

        $(
            #[test]
            fn $test() {
                assert_transcript($name);
            }
        )*
    };
}

transcript_tests! {
    transcript_default_alpha => "default_alpha",
    transcript_default_beta => "default_beta",
    transcript_default_stable => "default_stable",
    transcript_dkg => "dkg",
    transcript_very_large => "very_large",
    transcript_1_of_4_down => "1_of_4_down",
    transcript_1_of_3_down => "1_of_3_down",
    transcript_blinded_blocks_vmock => "blinded_blocks_vmock",
    transcript_pluto_keygen_create => "pluto_keygen_create",
    transcript_all_pluto => "all_pluto",
    transcript_mixed_2_charon_2_pluto => "mixed_2_charon_2_pluto",
    transcript_pluto_dkg => "pluto_dkg",
}

#[test]
fn every_scenario_has_a_transcript_test() {
    let names: Vec<&str> = smoke::scenarios().iter().map(|s| s.name).collect();
    assert_eq!(names, SCENARIO_NAMES);
}

#[test]
fn normalize_collapses_polls_and_placeholders() {
    let repo = Path::new("/work/repo");
    let raw = "git rev-parse --short=7 HEAD\t/work/repo\n\
               docker compose exec -T curl curl -s http://prometheus:9090/api/v1/rules?type=alert\t/tmp/c\n\
               sudo chown -R 501:20 .\t/tmp/c\n\
               sudo chmod -R a+wrX .\t/tmp/c\n";

    assert_eq!(
        normalize(raw, repo),
        "git rev-parse --short=7 HEAD\t<repo>\nsudo chown -R <uid>:<gid> .\t<dir>\nsudo chmod -R a+wrX .\t<dir>\npolls=yes\n"
    );
    assert_eq!(normalize("", repo), "polls=no\n");
    assert_eq!(
        normalize_owner("sudo chown -R root:wheel ."),
        "sudo chown -R root:wheel ."
    );
}
