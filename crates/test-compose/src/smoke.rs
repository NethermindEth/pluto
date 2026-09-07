//! The smoke scenario matrix: cluster configurations that are stood up with
//! docker compose and watched for alerts by the integration tests.
//!
//! The matrix is library code so the docker-based tests, the docker-free
//! transcript tests and the CI workflow all run the same scenarios.

use std::{env, path::PathBuf, time::Duration};

use crate::{
    auto::{AutoConfig, TmplFn},
    config::{Config, KeyGen, NodeImpl, VcType},
    define::{BROADCAST_RULE, ERROR_RATE_RULE, VAPI_RATE_RULE},
    template::TmplData,
};

/// The charon release the smoke clusters run.
pub const CHARON_IMAGE_TAG: &str = "v1.7.1";

/// How long a scenario keeps its cluster running while collecting alerts,
/// unless the scenario sets its own timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2 * 60);

/// Environment variable naming an external relay for the clusters to use
/// instead of the bundled one.
pub const EXTERNAL_RELAY_ENV: &str = "SMOKE_EXTERNAL_RELAY";

/// Environment variable pointing at the pluto checkout the `pluto:local`
/// image is built from. Scenarios that need it are skipped when it is unset.
pub const PLUTO_REPO_ENV: &str = "PLUTO_REPO";

/// The config every scenario starts from: monitoring off, ports unexposed,
/// insecure keys, a mock validator client and the pinned charon release.
pub fn base_config() -> Config {
    let mut conf = Config::new_default();
    conf.monitoring = false;
    conf.disable_monitoring_ports = true;
    conf.image_tag = CHARON_IMAGE_TAG.to_string();
    conf.insecure_keys = true;
    conf.vcs = vec![VcType::Mock];

    if let Ok(relay) = env::var(EXTERNAL_RELAY_ENV)
        && !relay.is_empty()
    {
        conf.external_relay = relay;
    }

    conf
}

/// One entry of the smoke matrix.
#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    /// Unique scenario name, also the test name.
    pub name: &'static str,
    /// Adjusts the base config.
    pub config_fn: Option<fn(&mut Config)>,
    /// Adjusts the run step template data.
    pub run_tmpl_fn: Option<fn(&mut TmplData)>,
    /// Adjusts the define step template data.
    pub define_tmpl_fn: Option<fn(&mut TmplData)>,
    /// Print `docker-compose.yml` after each step.
    pub print_yml: bool,
    /// Alert observation window; zero means [`DEFAULT_TIMEOUT`].
    pub timeout: Duration,
    /// The scenario builds and runs pluto, so it needs [`PLUTO_REPO_ENV`].
    pub require_pluto: bool,
}

impl Scenario {
    const fn new(name: &'static str) -> Self {
        Self {
            name,
            config_fn: None,
            run_tmpl_fn: None,
            define_tmpl_fn: None,
            print_yml: false,
            timeout: Duration::ZERO,
            require_pluto: false,
        }
    }

    /// The scenario's cluster config.
    pub fn config(&self) -> Config {
        let mut conf = base_config();
        if let Some(config_fn) = self.config_fn {
            config_fn(&mut conf);
        }

        conf
    }

    /// The alert observation window.
    pub fn timeout(&self) -> Duration {
        if self.timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            self.timeout
        }
    }

    /// An [`AutoConfig`] running this scenario in compose directory `dir`.
    pub fn auto_config(&self, dir: impl Into<PathBuf>) -> AutoConfig {
        let mut conf = AutoConfig::new(dir);
        conf.alert_timeout = self.timeout();
        conf.print_yml = self.print_yml;
        conf.run_tmpl_fn = self.run_tmpl_fn.map(|f| Box::new(f) as TmplFn);
        conf.define_tmpl_fn = self.define_tmpl_fn.map(|f| Box::new(f) as TmplFn);

        conf
    }
}

/// Renames node0's `p2p*` environment variables so they are not applied,
/// leaving the node unable to join the cluster.
fn unset_node0_p2p(data: &mut TmplData) {
    if let Some(node0) = data.nodes.first_mut() {
        for kv in &mut node0.env_vars {
            if kv.key.starts_with("p2p") {
                kv.key.push_str("-unset");
            }
        }
    }
}

/// The smoke matrix.
pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            print_yml: true,
            config_fn: Some(|conf| {
                conf.key_gen = KeyGen::Create;
                conf.feature_set = "alpha".to_string();
            }),
            ..Scenario::new("default_alpha")
        },
        Scenario {
            config_fn: Some(|conf| {
                conf.num_nodes = 3;
                conf.threshold = 2;
                conf.key_gen = KeyGen::Create;
                conf.feature_set = "beta".to_string();
            }),
            ..Scenario::new("default_beta")
        },
        Scenario {
            config_fn: Some(|conf| {
                conf.key_gen = KeyGen::Create;
                conf.feature_set = "stable".to_string();
            }),
            ..Scenario::new("default_stable")
        },
        Scenario {
            config_fn: Some(|conf| {
                conf.key_gen = KeyGen::Dkg;
            }),
            ..Scenario::new("dkg")
        },
        Scenario {
            config_fn: Some(|conf| {
                conf.num_nodes = 10;
                conf.threshold = 7;
                conf.num_validators = 100;
                conf.key_gen = KeyGen::Create;
                conf.slot_duration = Duration::from_secs(6);
                conf.synthetic_block_proposals = false;
            }),
            timeout: Duration::from_secs(3 * 60),
            ..Scenario::new("very_large")
        },
        Scenario {
            config_fn: Some(|conf| {
                conf.alert_exclude_jobs = vec!["node0".to_string()];
                conf.alert_disable_rules = vec![
                    ERROR_RATE_RULE.to_string(),
                    VAPI_RATE_RULE.to_string(),
                    BROADCAST_RULE.to_string(),
                ];
            }),
            run_tmpl_fn: Some(unset_node0_p2p),
            ..Scenario::new("1_of_4_down")
        },
        Scenario {
            config_fn: Some(|conf| {
                conf.num_nodes = 3;
                conf.threshold = 2;
                conf.alert_exclude_jobs = vec!["node0".to_string()];
                conf.alert_disable_rules =
                    vec![ERROR_RATE_RULE.to_string(), VAPI_RATE_RULE.to_string()];
            }),
            run_tmpl_fn: Some(unset_node0_p2p),
            ..Scenario::new("1_of_3_down")
        },
        Scenario {
            config_fn: Some(|conf| {
                conf.builder_api = true;
            }),
            ..Scenario::new("blinded_blocks_vmock")
        },
        Scenario {
            require_pluto: true,
            config_fn: Some(|conf| {
                conf.key_gen = KeyGen::Create;
                conf.key_gen_impl = Some(NodeImpl::Pluto);
            }),
            ..Scenario::new("pluto_keygen_create")
        },
        Scenario {
            require_pluto: true,
            config_fn: Some(|conf| {
                conf.key_gen = KeyGen::Create;
                conf.node_impls = vec![NodeImpl::Pluto];
                conf.synthetic_block_proposals = false;
            }),
            ..Scenario::new("all_pluto")
        },
        Scenario {
            require_pluto: true,
            config_fn: Some(|conf| {
                conf.key_gen = KeyGen::Create;
                conf.node_impls = vec![
                    NodeImpl::Charon,
                    NodeImpl::Charon,
                    NodeImpl::Pluto,
                    NodeImpl::Pluto,
                ];
                conf.synthetic_block_proposals = false;
            }),
            ..Scenario::new("mixed_2_charon_2_pluto")
        },
        Scenario {
            require_pluto: true,
            config_fn: Some(|conf| {
                conf.key_gen = KeyGen::Dkg;
                conf.node_impls = vec![NodeImpl::Pluto];
                conf.synthetic_block_proposals = false;
            }),
            ..Scenario::new("pluto_dkg")
        },
    ]
}

/// Looks a scenario up by name.
pub fn scenario(name: impl AsRef<str>) -> Option<Scenario> {
    let name = name.as_ref();
    scenarios()
        .into_iter()
        .find(|scenario| scenario.name == name)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::{
        config::{load_config, write_config},
        template::{Kv, TmplNode},
    };

    #[test]
    fn scenario_matrix() {
        let scenarios = scenarios();
        let mut names = HashSet::new();

        for scenario in &scenarios {
            assert!(!scenario.name.is_empty(), "scenario without a name");
            assert!(
                names.insert(scenario.name),
                "duplicate scenario name: {}",
                scenario.name
            );

            let conf = scenario.config();
            assert_eq!(
                scenario.require_pluto,
                conf.uses_pluto(),
                "{}: require_pluto must match the config",
                scenario.name
            );

            let dir = tempfile::tempdir().expect("tempdir");
            write_config(dir.path(), &conf).expect("write config");
            let loaded = load_config(dir.path()).expect("load config");
            assert_eq!(loaded, conf, "{}: config round trip", scenario.name);
        }

        assert_eq!(scenarios.len(), 12);
    }

    #[test]
    fn timeouts() {
        assert_eq!(
            scenario("default_alpha").expect("scenario").timeout(),
            Duration::from_secs(120)
        );
        assert_eq!(
            scenario("very_large").expect("scenario").timeout(),
            Duration::from_secs(180)
        );
        assert!(scenario("missing").is_none());
    }

    #[test]
    fn auto_config_carries_scenario_knobs() {
        let conf = scenario("1_of_4_down")
            .expect("scenario")
            .auto_config("/tmp/compose");

        assert_eq!(conf.alert_timeout, DEFAULT_TIMEOUT);
        assert!(!conf.print_yml);
        assert!(conf.run_tmpl_fn.is_some());
        assert!(conf.define_tmpl_fn.is_none());
        assert!(
            scenario("default_alpha")
                .expect("scenario")
                .auto_config("/tmp/compose")
                .print_yml
        );
    }

    #[test]
    fn unset_node0_p2p_renames_only_node0_p2p_keys() {
        let node = |keys: &[&str]| TmplNode {
            env_vars: keys.iter().map(|key| Kv::new(*key, "v")).collect(),
            ..TmplNode::default()
        };
        let mut data = TmplData {
            nodes: vec![
                node(&["p2p-relays", "log-level", "p2p-tcp-address"]),
                node(&["p2p-relays"]),
            ],
            ..TmplData::default()
        };

        unset_node0_p2p(&mut data);

        let keys = |index: usize| -> Vec<&str> {
            data.nodes[index]
                .env_vars
                .iter()
                .map(|kv| kv.key.as_str())
                .collect()
        };
        assert_eq!(
            keys(0),
            vec!["p2p-relays-unset", "log-level", "p2p-tcp-address-unset"]
        );
        assert_eq!(keys(1), vec!["p2p-relays"]);
    }

    #[test]
    fn unset_node0_p2p_tolerates_no_nodes() {
        let mut data = TmplData::default();
        unset_node0_p2p(&mut data);
        assert!(data.nodes.is_empty());
    }
}
