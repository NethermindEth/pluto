//! Cluster definition step and local image builds.

use std::{
    collections::BTreeSet,
    fs, io,
    path::{self, Component, Path, PathBuf},
    process::Command,
};

use k256::{SecretKey, elliptic_curve::rand_core::OsRng};
use pluto_eth2util::{enr::Record, network::GOERLI};
use tracing::info;

use crate::{
    Result,
    config::{CHARON_IMAGE, CMD_CREATE_DKG, Config, KeyGen, NodeImpl, Step, write_config},
    error::{CommandError, ComposeError},
    fsutil::{env_non_empty, write_file},
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

/// Every alert rule [`alert_rules`] can generate; `alert_disable_rules`
/// entries must name one of these.
pub const ALERT_RULE_NAMES: [&str; 6] = [
    PLUTO_DOWN_RULE,
    ERROR_RATE_RULE,
    WARN_RATE_RULE,
    VAPI_RATE_RULE,
    PROXY_RATE_RULE,
    BROADCAST_RULE,
];

/// Generator for node p2p private keys.
pub type KeyGenFn = fn() -> SecretKey;

/// Knobs for [`define`] that tests override.
#[derive(Debug, Clone, Copy)]
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
            key_gen: || SecretKey::random(&mut OsRng),
        }
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
        build_local(NodeImpl::Charon)?;
    }

    if opts.pull_images && !conf.build_local && conf.image_tag == "latest" {
        pull_latest()?;
    }

    if opts.pull_images && conf.uses_pluto() && conf.pluto_image_tag == "local" {
        build_local(NodeImpl::Pluto)?;
    }

    if !conf.split_keys_dir.is_empty() {
        rel_split_keys_dir(dir, &conf.split_keys_dir)?;
    }

    let data = if conf.key_gen == KeyGen::Dkg {
        info!("Creating node*/charon-enr-private-key for ENRs required for charon create dkg");

        // charon create dkg requires operator ENRs, so we need to create
        // p2pkeys now.
        let mut enrs = Vec::with_capacity(conf.num_nodes);

        for i in 0..conf.num_nodes {
            let key = (opts.key_gen)();

            // Best effort creation of folder, rather fail when saving p2pkey
            // file next.
            let node_dir = dir.join(format!("node{i}"));
            let _ = mkdir_all(&node_dir, 0o755);

            pluto_k1util::save(&key, &node_dir.join("charon-enr-private-key"))?;

            enrs.push(Record::from_key(&key)?.to_string());
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

    let prom_dir = dir.join("prometheus");
    mkdir_all(&prom_dir, 0o755).map_err(ComposeError::io("mkdir prometheus"))?;
    write_file(
        prom_dir.join("prometheus.yml"),
        prometheus_config(&conf),
        0o644,
    )
    .map_err(ComposeError::io("write prometheus.yml"))?;
    write_file(prom_dir.join("rules.yml"), alert_rules(&conf), 0o644)
        .map_err(ComposeError::io("write rules.yml"))?;

    info!("Creating docker-compose.yml");
    info!("Create cluster definition: docker compose up");

    write_docker_compose(dir, &data)?;

    Ok(data)
}

/// Returns the non-empty `split_keys_dir` relative to the compose dir `dir`,
/// both resolved against the working directory. Fails unless it lies inside
/// `dir`; `..` components are rejected rather than resolved.
pub(crate) fn rel_split_keys_dir(dir: &Path, split_keys_dir: &str) -> Result<PathBuf> {
    let not_child = || ComposeError::SplitKeysDirNotChild {
        split_keys_dir: split_keys_dir.to_string(),
        dir: dir.display().to_string(),
    };

    let base = path::absolute(dir).map_err(ComposeError::io("abs dir"))?;
    let target = path::absolute(split_keys_dir).map_err(ComposeError::io("abs dir"))?;
    let rel = target.strip_prefix(&base).map_err(|_| not_child())?;

    if rel.components().any(|c| c == Component::ParentDir) {
        return Err(not_child());
    }

    Ok(rel.to_path_buf())
}

/// Pulls the latest charon docker image.
fn pull_latest() -> Result<()> {
    info!("Pulling latest charon docker image");

    let status = Command::new("docker")
        .args(["pull", &format!("{CHARON_IMAGE}:latest")])
        .status();

    CommandError::check(status).map_err(ComposeError::exec("run docker pull"))
}

/// Builds the `:local` docker image of `node_impl` from the checkout its repo
/// environment variable points at.
///
/// For pluto the repo's short git hash is baked in as `GIT_COMMIT_HASH_SHORT`
/// when available: peers exchange it over peerinfo and warn about an empty or
/// unparseable hash.
pub fn build_local(node_impl: NodeImpl) -> Result<()> {
    let var = node_impl.repo_env();
    let repo = env_non_empty(var).ok_or(ComposeError::RepoNotSet { node_impl, var })?;
    let image = node_impl.local_image();

    info!(repo = %repo, "Building `{image}` docker container");

    let mut args = vec!["build".to_string(), "-t".to_string(), image];

    let git_hash = match node_impl {
        NodeImpl::Pluto => git_commit_hash_short(&repo).ok(),
        NodeImpl::Charon => None,
    };
    if let Some(hash) = git_hash {
        args.push("--build-arg".to_string());
        args.push(format!("GIT_COMMIT_HASH_SHORT={hash}"));
    }

    args.push(".".to_string());

    let output = Command::new("docker")
        .args(&args)
        .current_dir(&repo)
        .output();

    CommandError::check_output(output)
        .map(drop)
        .map_err(ComposeError::exec("exec docker build"))
}

/// Returns the repo's short (7 char) commit hash.
fn git_commit_hash_short(repo: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .current_dir(repo)
        .output();

    let output = CommandError::check_output(output).map_err(ComposeError::exec("git rev-parse"))?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Copies the embedded static folders to the compose dir; scripts are made
/// executable.
fn copy_static_folders(dir: &Path) -> Result<()> {
    let sub_dirs: BTreeSet<&str> = STATIC_FILES.iter().map(|file| file.dir).collect();
    for sub_dir in sub_dirs {
        mkdir_all(dir.join(sub_dir), 0o755).map_err(ComposeError::io("mkdir all"))?;
    }

    for file in STATIC_FILES {
        let mode = if file.name.ends_with(".sh") {
            0o755
        } else {
            0o644
        };

        write_file(dir.join(file.dir).join(file.name), file.bytes, mode)
            .map_err(ComposeError::io("write file"))?;
    }

    Ok(())
}

/// Renders Prometheus scrape configs for the actual cluster size, replacing
/// the static default: the relay plus every node, so the `up == 0` alert
/// sees all of them.
pub(crate) fn prometheus_config(conf: &Config) -> String {
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

    b
}

/// Renders the Prometheus alert rules the smoke test gates on.
///
/// `alert_exclude_jobs` exempts jobs from every behavioural rule (never from
/// `Pluto Down`); `alert_disable_rules` drops whole rules by name.
pub(crate) fn alert_rules(conf: &Config) -> String {
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

    // Mock artefacts, not node behaviour: vmock warns before the first epoch,
    // the tracker about broadcasts the mock beacon node never includes.
    let warn_topics = "vmock|tracker";

    // `0 * up` gives every node job a zero series so a node that never
    // broadcast (no counter yet) alerts too; summed per job, node jobs only.
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
        // Windowed, unlike charon's absolute `> 0`: a fresh simnet cluster logs
        // one consensus timeout per node at the first epoch boundary.
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

    let blocks: Vec<&str> = rule_blocks
        .iter()
        .filter(|(name, _)| !conf.alert_disable_rules.iter().any(|rule| rule == name))
        .map(|(_, block)| block.as_str())
        .collect();

    format!("groups:\n- name: pluto\n  rules:\n{}", blocks.join("\n"))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated scrape config covers every configured node plus the
    /// relay, so the `up == 0` and injected-zero broadcast alerts see all of
    /// them.
    #[test]
    fn prometheus_config_scrapes_all_nodes() {
        let mut conf = Config::new_default();
        conf.num_nodes = 10;

        let content = prometheus_config(&conf);
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
    fn alert_rules_broadcast_covers_missing_series() {
        let content = alert_rules(&Config::new_default());

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
    fn alert_rules_excludes_degraded_jobs() {
        let mut conf = Config::new_default();
        conf.alert_exclude_jobs = vec!["node0".to_string()];

        let content = alert_rules(&conf);

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
    fn alert_rules_warn_topics() {
        let content = alert_rules(&Config::new_default());
        assert!(
            content.contains(r#"increase(app_log_warn_total{topic!~"vmock|tracker"}[30s]) > 2"#),
            "{content}"
        );
    }

    /// Charon's dead "Outstanding Duty Rate" rule stays removed: broadcast
    /// counts can never exceed scheduled counts, so it could never fire.
    #[test]
    fn alert_rules_drops_outstanding_duty() {
        let content = alert_rules(&Config::new_default());
        assert!(!content.contains("Outstanding Duty"), "{content}");
        assert!(!content.contains("core_scheduler_duty_total"), "{content}");
    }

    /// `alert_disable_rules` drops exactly the named rules and validation
    /// rejects unknown names.
    #[test]
    fn alert_rules_disable_rules() {
        let mut conf = Config::new_default();
        conf.alert_disable_rules = vec![ERROR_RATE_RULE.to_string(), VAPI_RATE_RULE.to_string()];

        let content = alert_rules(&conf);
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

    /// The split keys dir must lie inside the compose dir: a nested dir is
    /// accepted (as its relative path), a sibling and a `..` escape are not.
    #[test]
    fn rel_split_keys_dir_requires_a_child() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("compose");
        let dir = dir.as_path();

        let keys = dir.join("keys").display().to_string();
        assert_eq!(
            rel_split_keys_dir(dir, &keys).expect("child"),
            Path::new("keys")
        );

        let sibling = root.path().join("keys").display().to_string();
        let err = rel_split_keys_dir(dir, &sibling).expect_err("sibling");
        assert!(
            matches!(err, ComposeError::SplitKeysDirNotChild { .. }),
            "{err:?}"
        );

        let escape = dir.join("../keys").display().to_string();
        let err = rel_split_keys_dir(dir, &escape).expect_err("escape");
        assert!(
            matches!(err, ComposeError::SplitKeysDirNotChild { .. }),
            "{err:?}"
        );
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
}
