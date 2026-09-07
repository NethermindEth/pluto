//! Cluster definition step, compose directory cleaning and image builds.

use std::{
    env, fmt, fs, io,
    path::Path,
    process::{Command, Output},
};

use k256::{SecretKey, elliptic_curve::rand_core::OsRng};
use pluto_eth2util::{enr::Record, network::GOERLI};
use tracing::info;

use crate::{
    Result,
    config::{CMD_CREATE_DKG, CONFIG_FILE, Config, KeyGen, Step, write_config},
    error::{CommandError, ComposeError},
    fsutil::{go_abs, go_path_join, go_rel, write_file},
    static_files::STATIC_FILES,
    template::{Kv, TmplData, TmplNode, write_docker_compose},
};

/// The zero address, quoted for the compose environment: not owned by any
/// user and commonly used as a generic null address.
pub(crate) const ZERO_ADDRESS: &str = r#""0x0000000000000000000000000000000000000000""#;

/// Alert rule: a node stopped answering scrapes.
pub const PLUTO_DOWN_RULE: &str = "Pluto Down";
/// Alert rule: error logs in the last 30 seconds.
pub const ERROR_RATE_RULE: &str = "Error Log Rate";
/// Alert rule: more than two warning logs in the last 30 seconds.
pub const WARN_RATE_RULE: &str = "Warn Log Rate";
/// Alert rule: validator API errors (excluding the proxy).
pub const VAPI_RATE_RULE: &str = "Validator API Error Rate";
/// Alert rule: proxied validator API errors.
pub const PROXY_RATE_RULE: &str = "Proxy API Error Rate";
/// Alert rule: fewer than half a duty broadcast per 30 seconds.
pub const BROADCAST_RULE: &str = "Broadcast Duty Rate";

/// Every alert rule `write_alert_rules` can generate; `alert_disable_rules`
/// entries must name one of these.
pub const ALERT_RULE_NAMES: [&str; 6] = [
    PLUTO_DOWN_RULE,
    ERROR_RATE_RULE,
    WARN_RATE_RULE,
    VAPI_RATE_RULE,
    PROXY_RATE_RULE,
    BROADCAST_RULE,
];

/// Error a key generator may return.
pub type KeyGenError = Box<dyn std::error::Error + Send + Sync>;

/// Generator for node p2p private keys.
pub type KeyGenFn = Box<dyn Fn() -> std::result::Result<SecretKey, KeyGenError> + Send + Sync>;

/// Knobs for [`define`] that are process-wide toggles in the Go harness.
pub struct DefineOptions {
    /// Pull the `latest` charon image and build `pluto:local` when the config
    /// asks for them. Disabled by tests, which have no docker.
    pub pull_images: bool,
    /// Generator for the per-node ENR private keys of DKG clusters. Tests
    /// swap in a deterministic generator to get reproducible ENRs.
    pub key_gen: KeyGenFn,
}

impl Default for DefineOptions {
    fn default() -> Self {
        Self {
            pull_images: true,
            key_gen: Box::new(|| Ok(SecretKey::random(&mut OsRng))),
        }
    }
}

impl fmt::Debug for DefineOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefineOptions")
            .field("pull_images", &self.pull_images)
            .field("key_gen", &"<fn>")
            .finish()
    }
}

/// Deletes all compose artefacts in `dir`.
///
/// The directory is only cleaned when its listing contains a `config.json`
/// entry whose full path is exactly `config.json`, i.e. when `dir` is the
/// working directory; anything else is reported as "config.json not found"
/// and left alone. Entries with `key` in their path are never deleted so a
/// long-lived split-keys folder survives.
pub fn clean(dir: impl AsRef<Path>) -> Result<()> {
    let dir = dir.as_ref().to_string_lossy();
    let files = glob_all(&dir);

    // Make sure we ONLY delete compose artifacts.
    let mut config_found = false;
    let mut go_found = false;

    for file in &files {
        if file == CONFIG_FILE {
            config_found = true;
        } else if file.ends_with(".go") || file.starts_with("go.") {
            go_found = true;
        }
    }

    if !config_found {
        info!("Not cleaning since config.json not found");
        return Ok(());
    } else if go_found {
        return Err(ComposeError::GoFilesFound {
            dir: dir.into_owned(),
        });
    }

    info!(files = files.len(), "Cleaning compose dir");

    for file in &files {
        if file.contains("key") {
            // Do not delete root folder with key in the name, since it might be
            // long-lived split keys folder.
            info!(path = %file, "Not deleting *key* folder");
            continue;
        }

        remove_all(file).map_err(ComposeError::RemoveFile)?;
    }

    Ok(())
}

/// Lists `dir/*` the way Go's `filepath.Glob(path.Join(dir, "*"))` does:
/// sorted, dotfiles included, each entry joined onto the cleaned directory,
/// and an unreadable or missing directory yielding no entries.
fn glob_all(dir: &str) -> Vec<String> {
    let pattern = go_path_join(dir, "*");
    let dir_part = match pattern.rfind('/') {
        Some(i) => &pattern[..=i],
        None => "",
    };
    let dir_part = match dir_part {
        "" => ".",
        "/" => "/",
        d => d.strip_suffix('/').unwrap_or(d),
    };

    let Ok(entries) = fs::read_dir(dir_part) else {
        return Vec::new();
    };

    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort_unstable();

    names
        .iter()
        .map(|name| go_path_join(dir_part, name))
        .collect()
}

/// Removes a file or directory tree; a missing path is not an error.
fn remove_all(path: &str) -> io::Result<()> {
    let result = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(err) => Err(err),
    };

    match result {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Creates `path` and its parents with `mode` (subject to the umask).
pub(crate) fn mkdir_all(path: impl AsRef<Path>, mode: u32) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;

    builder.create(path)
}

/// Defines a compose cluster: writes the `defined` config, the static
/// monitoring files, the Prometheus scrape config and alert rules, and a
/// `docker-compose.yml` that either runs `charon create dkg` (DKG key
/// generation) or a no-op echo container (`create` key generation).
///
/// For DKG clusters the per-node ENR private keys are generated with
/// `opts.key_gen` and saved as `node<i>/charon-enr-private-key`.
pub fn define(dir: impl AsRef<Path>, mut conf: Config, opts: &DefineOptions) -> Result<TmplData> {
    let dir = dir.as_ref();
    let dir_str = dir.to_string_lossy().into_owned();

    if conf.step != Step::New {
        return Err(ComposeError::NotNew { step: conf.step });
    }

    if conf.build_local {
        build_local()?;
    }

    if opts.pull_images && !conf.build_local && conf.image_tag == "latest" {
        pull_latest()?;
    }

    if opts.pull_images && conf.uses_pluto() && conf.pluto_image_tag == "local" {
        build_local_pluto()?;
    }

    if !conf.split_keys_dir.is_empty() {
        validate_split_keys_dir(&dir_str, &conf.split_keys_dir)?;
    }

    let data = if conf.key_gen == KeyGen::Dkg {
        info!("Creating node*/charon-enr-private-key for ENRs required for charon create dkg");

        // charon create dkg requires operator ENRs, so we need to create
        // p2pkeys now.
        let p2pkeys = new_p2p_keys(conf.num_nodes, &opts.key_gen)?;

        let mut enrs = Vec::with_capacity(p2pkeys.len());

        for (i, key) in p2pkeys.iter().enumerate() {
            // Best effort creation of folder, rather fail when saving p2pkey
            // file next.
            let _ = mkdir_all(node_file(&dir_str, i, ""), 0o755);

            let key_file = node_file(&dir_str, i, "charon-enr-private-key");
            pluto_k1util::save(key, Path::new(&key_file))
                .map_err(ComposeError::SaveEnrPrivateKey)?;

            let record = Record::from_key(key)?;
            enrs.push(record.to_string());
        }

        let kvs = vec![
            Kv::new("name", "compose"),
            Kv::new("num_validators", conf.num_validators.to_string()),
            Kv::new("operator_enrs", enrs.join(",")),
            Kv::new("threshold", conf.threshold.to_string()),
            Kv::new("withdrawal_addresses", ZERO_ADDRESS),
            Kv::new("fee-recipient_addresses", ZERO_ADDRESS),
            Kv::new("dkg_algorithm", "frost"),
            Kv::new("output_dir", "/compose"),
            Kv::new("network", GOERLI.name),
        ];

        let node = TmplNode {
            image: conf.image_override(conf.keygen_impl()),
            env_vars: kvs,
            ..TmplNode::default()
        };

        TmplData {
            compose_dir: dir_str.clone(),
            charon_image_tag: conf.image_tag.clone(),
            charon_command: CMD_CREATE_DKG.to_string(),
            nodes: vec![node],
            ..TmplData::default()
        }
    } else {
        // Other keygens only need a noop docker compose, since
        // charon-compose.yml is used directly in their compose lock.
        let key_gen = conf.key_gen;

        TmplData {
            compose_dir: dir_str.clone(),
            charon_image_tag: conf.image_tag.clone(),
            charon_entrypoint: "echo".to_string(),
            charon_command: format!("No charon commands needed for keygen={key_gen} define step"),
            nodes: vec![TmplNode::default()],
            ..TmplData::default()
        }
    };

    info!("Creating config.json");

    conf.step = Step::Defined;
    write_config(dir, &conf)?;

    copy_static_folders(dir)?;
    write_prometheus_config(dir, &conf)?;
    write_alert_rules(dir, &conf)?;

    info!("Creating docker-compose.yml");
    info!("Create cluster definition: docker compose up");

    write_docker_compose(dir, &data)?;

    Ok(data)
}

/// Fails unless the split keys dir is a child of the compose dir.
fn validate_split_keys_dir(dir: &str, split_keys_dir: &str) -> Result<()> {
    let rel = rel_split_keys_dir(dir, split_keys_dir)?;
    if rel.starts_with("..") {
        return Err(ComposeError::SplitKeysDirNotChild { relative: rel });
    }

    Ok(())
}

/// Returns `split_keys_dir` relative to `dir`, or empty when unset.
pub(crate) fn rel_split_keys_dir(dir: &str, split_keys_dir: &str) -> Result<String> {
    if split_keys_dir.is_empty() {
        return Ok(String::new());
    }

    let base = go_abs(dir).map_err(ComposeError::AbsDir)?;
    let target = go_abs(split_keys_dir).map_err(ComposeError::AbsDir)?;

    go_rel(&base, &target).ok_or(ComposeError::RelativeSplitKeysDir { base, target })
}

/// Pulls the latest charon docker image.
fn pull_latest() -> Result<()> {
    info!("Pulling latest charon docker image");

    let status = Command::new("docker")
        .args(["pull", "obolnetwork/charon:latest"])
        .status()
        .map_err(|err| ComposeError::RunDockerPull(CommandError::Io(err)))?;

    if !status.success() {
        return Err(ComposeError::RunDockerPull(CommandError::Exit(status)));
    }

    Ok(())
}

/// Builds the `obolnetwork/charon:local` docker image from the checkout the
/// `CHARON_REPO` environment variable points at.
pub fn build_local() -> Result<()> {
    let repo = repo_from_env("CHARON_REPO").ok_or(ComposeError::CharonRepoNotSet)?;

    info!(repo = %repo, "Building `obolnetwork/charon:local` docker container");

    docker_build(&repo, &["build", "-t", "obolnetwork/charon:local", "."])
}

/// Builds the `pluto:local` docker image from the checkout the `PLUTO_REPO`
/// environment variable points at.
///
/// The repo's short git hash is baked in as `GIT_COMMIT_HASH_SHORT` when
/// available: peers exchange it over peerinfo and warn about an empty or
/// unparseable hash.
pub fn build_local_pluto() -> Result<()> {
    let repo = repo_from_env("PLUTO_REPO").ok_or(ComposeError::PlutoRepoNotSet)?;

    info!(repo = %repo, "Building `pluto:local` docker container");

    let mut args = vec![
        "build".to_string(),
        "-t".to_string(),
        "pluto:local".to_string(),
    ];

    if let Ok(hash) = git_commit_hash_short(&repo) {
        args.push("--build-arg".to_string());
        args.push(format!("GIT_COMMIT_HASH_SHORT={hash}"));
    }

    args.push(".".to_string());

    docker_build(&repo, &args)
}

/// Reads a repo path from the environment; unset, empty or non-UTF-8 values
/// count as not set.
fn repo_from_env(var: &str) -> Option<String> {
    env::var(var).ok().filter(|repo| !repo.is_empty())
}

/// Runs `docker <args>` in `repo`, reporting the combined output on failure.
fn docker_build<S: AsRef<std::ffi::OsStr>>(repo: &str, args: &[S]) -> Result<()> {
    let output = Command::new("docker")
        .args(args)
        .current_dir(repo)
        .output()
        .map_err(|err| ComposeError::ExecDockerBuild {
            source: CommandError::Io(err),
            output: String::new(),
        })?;

    if !output.status.success() {
        return Err(ComposeError::ExecDockerBuild {
            source: CommandError::Exit(output.status),
            output: combined_output(&output),
        });
    }

    Ok(())
}

/// Joins captured stdout and stderr, lossily decoded.
pub(crate) fn combined_output(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

/// Returns the repo's short (7 char) commit hash.
fn git_commit_hash_short(repo: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .current_dir(repo)
        .output()
        .map_err(|err| ComposeError::GitRevParse(CommandError::Io(err)))?;

    if !output.status.success() {
        return Err(ComposeError::GitRevParse(CommandError::Exit(output.status)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Copies the embedded static folders to the compose dir; scripts are made
/// executable.
fn copy_static_folders(dir: &Path) -> Result<()> {
    for file in STATIC_FILES {
        let sub_dir = dir.join(file.dir);
        mkdir_all(&sub_dir, 0o755).map_err(ComposeError::MkdirAll)?;

        let mode = if file.name.ends_with(".sh") {
            0o755
        } else {
            0o644
        };

        write_file(sub_dir.join(file.name), file.bytes, mode).map_err(ComposeError::WriteFile)?;
    }

    Ok(())
}

/// Writes Prometheus scrape configs for the actual cluster size, replacing
/// the static default: the relay plus every node, so the `up == 0` alert
/// sees all of them.
pub(crate) fn write_prometheus_config(dir: &Path, conf: &Config) -> Result<()> {
    let mut b = String::from(
        "global:
  scrape_interval:     5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: 'relay'
    static_configs:
      - targets: [ 'relay:3620' ]
",
    );

    for i in 0..conf.num_nodes {
        b.push_str(&format!(
            "  - job_name: 'node{i}'
    static_configs:
      - targets: ['node{i}:3620']
"
        ));
    }

    b.push_str(
        "
rule_files:
  - /etc/prometheus/rules.yml
",
    );

    let prom_dir = dir.join("prometheus");
    mkdir_all(&prom_dir, 0o755).map_err(ComposeError::MkdirPrometheus)?;

    write_file(prom_dir.join("prometheus.yml"), b, 0o644).map_err(ComposeError::WritePrometheusYml)
}

/// Writes the Prometheus alert rules the smoke test gates on.
///
/// `alert_exclude_jobs` exempts jobs from every behavioural rule (never from
/// `Pluto Down`); `alert_disable_rules` drops whole rules by name.
pub(crate) fn write_alert_rules(dir: &Path, conf: &Config) -> Result<()> {
    // Label matcher excluding the configured jobs, or empty.
    let job_excl = if conf.alert_exclude_jobs.is_empty() {
        String::new()
    } else {
        let jobs = conf.alert_exclude_jobs.join("|");
        format!(r#"job!~"{jobs}""#)
    };

    // Builds a `{a,b}` selector from the non-empty matchers, or "".
    let sel = |matchers: &[&str]| -> String {
        let parts: Vec<&str> = matchers.iter().copied().filter(|m| !m.is_empty()).collect();
        if parts.is_empty() {
            String::new()
        } else {
            format!("{{{}}}", parts.join(","))
        }
    };

    // Warn topics that are mock artefacts, not node behaviour: the validator
    // mock warns about pending duties before the first epoch, and the tracker
    // warns about every broadcast the mock beacon node never includes on-chain.
    let warn_topics = "vmock|tracker";

    // Inject a zero for every scraped node job (`0 * up`) so a node with no
    // core_bcast_broadcast_total series at all (the counter is only created
    // on first broadcast) alerts too. Summed per job because the per-duty
    // sync_message series legitimately pauses most epochs. Scoped to node
    // jobs: the relay never broadcasts duties.
    let bcast_sel = sel(&[r#"job=~"node[0-9]+""#, &job_excl]);

    let error_sel = sel(&[&job_excl]);
    let warn_sel = sel(&[&format!(r#"topic!~"{warn_topics}""#), &job_excl]);
    let vapi_sel = sel(&[r#"endpoint!="proxy""#, &job_excl]);
    let proxy_sel = sel(&[r#"endpoint="proxy""#, &job_excl]);

    // Blocks keyed by rule name so conf.alert_disable_rules can drop whole
    // rules; the names double as the collector's warmup allowlist keys.
    let rule_blocks = [
        (
            PLUTO_DOWN_RULE,
            rule_block(PLUTO_DOWN_RULE, "up == 0", "is down"),
        ),
        // Windowed instead of charon's absolute app_log_error_total > 0: a
        // fresh simnet cluster logs exactly one consensus timeout error per
        // node at the first epoch boundary, which an absolute counter gate
        // could never recover from.
        (
            ERROR_RATE_RULE,
            rule_block(
                ERROR_RATE_RULE,
                &format!("increase(app_log_error_total{error_sel}[30s]) > 0"),
                "has a high error rate",
            ),
        ),
        (
            WARN_RATE_RULE,
            rule_block(
                WARN_RATE_RULE,
                &format!("increase(app_log_warn_total{warn_sel}[30s]) > 2"),
                "has a high warning rate",
            ),
        ),
        (
            VAPI_RATE_RULE,
            rule_block(
                VAPI_RATE_RULE,
                &format!("increase(core_validatorapi_request_error_total{vapi_sel}[30s]) > 1"),
                "validator API a high error rate",
            ),
        ),
        (
            PROXY_RATE_RULE,
            rule_block(
                PROXY_RATE_RULE,
                &format!("increase(core_validatorapi_request_error_total{proxy_sel}[30s]) > 5"),
                "proxy API a high error rate",
            ),
        ),
        (
            BROADCAST_RULE,
            rule_block(
                BROADCAST_RULE,
                &format!(
                    "(sum by (job) (increase(core_bcast_broadcast_total{bcast_sel}[30s])) or on (job) max by (job) (0 * up{bcast_sel})) < 0.5"
                ),
                "is not broadcasting enough duties",
            ),
        ),
    ];

    let mut b = String::from("groups:\n- name: pluto\n  rules:\n");

    for (name, block) in &rule_blocks {
        if conf.alert_disable_rules.iter().any(|rule| rule == name) {
            continue;
        }

        b.push_str(block);
        b.push('\n');
    }

    let rules = b.strip_suffix('\n').unwrap_or(&b);

    let prom_dir = dir.join("prometheus");
    mkdir_all(&prom_dir, 0o755).map_err(ComposeError::MkdirPrometheus)?;

    write_file(prom_dir.join("rules.yml"), rules, 0o644).map_err(ComposeError::WriteRulesYml)
}

/// Formats one alert rule block, firing after 15 seconds of `expr`.
fn rule_block(name: &str, expr: &str, description: &str) -> String {
    format!(
        "  - alert: {name}
    expr: {expr}
    for: 15s
    annotations:
      description: \"Pluto {{{{ $labels.job }}}} {description}\"
"
    )
}

/// Generates `n` node p2p private keys with `key_gen`.
fn new_p2p_keys(n: usize, key_gen: &KeyGenFn) -> Result<Vec<SecretKey>> {
    (0..n)
        .map(|_| key_gen().map_err(ComposeError::NewKey))
        .collect()
}

/// Returns the path of `file` in node `i`'s folder; the folder itself when
/// `file` is empty.
pub(crate) fn node_file(dir: &str, i: usize, file: &str) -> String {
    go_path_join(&go_path_join(dir, &format!("node{i}")), file)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// Writes alert rules for `conf` into a temp dir and returns them.
    fn write_rules(conf: &Config) -> String {
        let dir = tempfile::tempdir().expect("tempdir");
        write_alert_rules(dir.path(), conf).expect("write alert rules");

        fs::read_to_string(dir.path().join("prometheus").join("rules.yml")).expect("read rules.yml")
    }

    /// The generated scrape config covers every configured node plus the
    /// relay, so the `up == 0` and injected-zero broadcast alerts see all of
    /// them.
    #[test]
    fn write_prometheus_config_scrapes_all_nodes() {
        let dir = tempfile::tempdir().expect("tempdir");

        let mut conf = Config::new_default();
        conf.num_nodes = 10;

        write_prometheus_config(dir.path(), &conf).expect("write prometheus config");

        let content = fs::read_to_string(dir.path().join("prometheus").join("prometheus.yml"))
            .expect("read prometheus.yml");
        assert!(content.contains("- targets: [ 'relay:3620' ]"), "{content}");

        for i in 0..conf.num_nodes {
            assert!(
                content.contains(&format!("job_name: 'node{i}'")),
                "{content}"
            );
            assert!(
                content.contains(&format!("- targets: ['node{i}:3620']")),
                "{content}"
            );
        }

        assert!(
            !content.contains("node10"),
            "must not scrape beyond num_nodes: {content}"
        );
    }

    /// The broadcast liveness expression injects a zero for scraped node
    /// jobs with no core_bcast_broadcast_total series, so a node that never
    /// broadcasts fails instead of silently passing.
    #[test]
    fn write_alert_rules_broadcast_covers_missing_series() {
        let content = write_rules(&Config::new_default());

        assert!(
            content.contains(
                r#"expr: (sum by (job) (increase(core_bcast_broadcast_total{job=~"node[0-9]+"}[30s])) or on (job) max by (job) (0 * up{job=~"node[0-9]+"})) < 0.5"#
            ),
            "{content}"
        );
    }

    /// `alert_exclude_jobs` exempts a node from every behavioural rule while
    /// "Pluto Down" keeps watching it.
    #[test]
    fn write_alert_rules_excludes_degraded_jobs() {
        let mut conf = Config::new_default();
        conf.alert_exclude_jobs = vec!["node0".to_string()];

        let content = write_rules(&conf);

        assert!(
            content.contains(r#"increase(app_log_error_total{job!~"node0"}[30s]) > 0"#),
            "{content}"
        );
        assert!(
            content.contains(
                r#"increase(app_log_warn_total{topic!~"vmock|tracker",job!~"node0"}[30s]) > 2"#
            ),
            "{content}"
        );
        assert!(
            content.contains(
                r#"increase(core_validatorapi_request_error_total{endpoint!="proxy",job!~"node0"}[30s]) > 1"#
            ),
            "{content}"
        );
        assert!(
            content.contains(
                r#"increase(core_validatorapi_request_error_total{endpoint="proxy",job!~"node0"}[30s]) > 5"#
            ),
            "{content}"
        );
        assert!(
            content.contains(
                r#"(sum by (job) (increase(core_bcast_broadcast_total{job=~"node[0-9]+",job!~"node0"}[30s])) or on (job) max by (job) (0 * up{job=~"node[0-9]+",job!~"node0"})) < 0.5"#
            ),
            "{content}"
        );

        // The scrape-liveness rule must never carry exclusions.
        assert!(content.contains("expr: up == 0"), "{content}");
    }

    /// The Warn Log Rate gate excludes exactly the two charon mock-noise
    /// topics.
    #[test]
    fn write_alert_rules_warn_topics() {
        let content = write_rules(&Config::new_default());
        assert!(
            content.contains(r#"increase(app_log_warn_total{topic!~"vmock|tracker"}[30s]) > 2"#),
            "{content}"
        );
    }

    /// Charon's dead "Outstanding Duty Rate" rule stays removed: broadcast
    /// counts can never exceed scheduled counts, so it could never fire.
    #[test]
    fn write_alert_rules_drops_outstanding_duty() {
        let content = write_rules(&Config::new_default());
        assert!(!content.contains("Outstanding Duty"), "{content}");
        assert!(!content.contains("core_scheduler_duty_total"), "{content}");
    }

    /// `alert_disable_rules` drops exactly the named rules and validation
    /// rejects unknown names.
    #[test]
    fn write_alert_rules_disable_rules() {
        let mut conf = Config::new_default();
        conf.alert_disable_rules = vec![ERROR_RATE_RULE.to_string(), VAPI_RATE_RULE.to_string()];

        let content = write_rules(&conf);
        assert!(!content.contains("Error Log Rate"), "{content}");
        assert!(!content.contains(r#"endpoint!="proxy""#), "{content}");
        // The remaining gates stay.
        assert!(content.contains("Pluto Down"), "{content}");
        assert!(content.contains("Warn Log Rate"), "{content}");
        assert!(content.contains("Proxy API Error Rate"), "{content}");
        assert!(content.contains("Broadcast Duty Rate"), "{content}");

        let mut conf = Config::new_default();
        conf.alert_disable_rules = vec!["No Such Rule".to_string()];
        let dir = tempfile::tempdir().expect("tempdir");
        let err = write_config(dir.path(), &conf).expect_err("must reject unknown rule");
        assert!(err.to_string().contains("unknown alert rule name"), "{err}");
    }

    #[test]
    fn write_alert_rules_has_no_trailing_newline_and_all_rules() {
        let content = write_rules(&Config::new_default());
        assert!(content.starts_with("groups:\n- name: pluto\n  rules:\n"));
        // The blank-line separator after the last block is trimmed; the block's
        // own newline stays.
        assert!(content.ends_with("\"\n"), "{content:?}");
        assert!(!content.ends_with("\n\n"), "{content:?}");
        for name in ALERT_RULE_NAMES {
            assert!(
                content.contains(&format!("  - alert: {name}\n")),
                "{content}"
            );
        }
    }

    #[test]
    fn define_rejects_non_new_step() {
        let mut conf = Config::new_default();
        conf.step = Step::Locked;
        let dir = tempfile::tempdir().expect("tempdir");
        let err = define(dir.path(), conf, &DefineOptions::default()).expect_err("must fail");
        assert_eq!(
            err.to_string(),
            "compose config not new, so can't be defined: step=locked"
        );
    }

    #[test]
    fn define_rejects_split_keys_dir_outside_compose_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");

        let mut conf = Config::new_default();
        conf.split_keys_dir = outside.path().to_string_lossy().into_owned();

        let opts = DefineOptions {
            pull_images: false,
            ..DefineOptions::default()
        };
        let err = define(dir.path(), conf, &opts).expect_err("must fail");
        assert!(
            err.to_string()
                .starts_with("split-keys-dir must be a child of compose dir: relative=.."),
            "{err}"
        );
    }

    #[test]
    fn rel_split_keys_dir_variants() {
        assert_eq!(rel_split_keys_dir("/a/b", "").expect("empty"), "");
        assert_eq!(
            rel_split_keys_dir("/a/b", "/a/b/keys").expect("child"),
            "keys"
        );
        assert_eq!(
            rel_split_keys_dir("/a/b", "/a/keys").expect("sibling"),
            "../keys"
        );
    }

    #[test]
    fn clean_leaves_dir_when_config_path_is_not_bare() {
        // Entries are compared by full path, so a config.json below a real
        // directory is never recognised and nothing is deleted.
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join(CONFIG_FILE), "{}").expect("write config");
        fs::write(dir.path().join("docker-compose.yml"), "x").expect("write yml");

        clean(dir.path()).expect("clean");

        assert!(dir.path().join(CONFIG_FILE).exists());
        assert!(dir.path().join("docker-compose.yml").exists());
    }

    #[test]
    fn glob_all_lists_sorted_joined_entries_and_tolerates_missing_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("b"), "").expect("write");
        fs::write(dir.path().join("a"), "").expect("write");
        fs::write(dir.path().join(".hidden"), "").expect("write");

        let dir_str = dir.path().to_string_lossy().into_owned();
        let got = glob_all(&format!("{dir_str}/"));
        assert_eq!(
            got,
            vec![
                format!("{dir_str}/.hidden"),
                format!("{dir_str}/a"),
                format!("{dir_str}/b"),
            ]
        );

        assert!(glob_all(&format!("{dir_str}/does-not-exist")).is_empty());
    }

    #[test]
    fn node_file_paths() {
        assert_eq!(node_file("/c", 0, ""), "/c/node0");
        assert_eq!(
            node_file("/c/", 2, "charon-enr-private-key"),
            "/c/node2/charon-enr-private-key"
        );
        assert_eq!(node_file("", 1, ""), "node1");
    }

    #[test]
    fn copy_static_folders_writes_all_files_with_modes() {
        let dir = tempfile::tempdir().expect("tempdir");
        copy_static_folders(dir.path()).expect("copy");

        for file in STATIC_FILES {
            let path = dir.path().join(file.dir).join(file.name);
            assert_eq!(fs::read(&path).expect("read"), file.bytes, "{path:?}");

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
                let want = if file.name.ends_with(".sh") {
                    0o755
                } else {
                    0o644
                };
                assert_eq!(mode, want, "{path:?}");
            }
        }
    }
}
