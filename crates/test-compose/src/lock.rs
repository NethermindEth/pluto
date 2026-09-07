//! Cluster lock step and the shared node environment.

use std::path::Path;

use tracing::info;

use crate::{
    Result,
    config::{CMD_CREATE_CLUSTER, CMD_DKG, Config, KeyGen, Step, VcType, write_config},
    define::{ZERO_ADDRESS, rel_split_keys_dir},
    duration::go_duration_string,
    error::ComposeError,
    fsutil::go_path_join,
    template::{Kv, TmplData, TmplNode, write_docker_compose},
};

/// Writes the `locked` config and a `docker-compose.yml` that generates the
/// validator keys and cluster lock: a single `charon create cluster`
/// container for `create` key generation, or one `charon dkg` container per
/// node plus the relay for DKG.
pub fn lock(dir: impl AsRef<Path>, mut conf: Config) -> Result<TmplData> {
    let dir = dir.as_ref();
    let dir_str = dir.to_string_lossy().into_owned();

    if conf.step != Step::Defined {
        return Err(ComposeError::NotDefined { step: conf.step });
    }

    let data = match conf.key_gen {
        KeyGen::Create => {
            let mut split_keys_dir = rel_split_keys_dir(&dir_str, &conf.split_keys_dir)?;
            if !split_keys_dir.is_empty() {
                split_keys_dir = go_path_join("/compose", &split_keys_dir);
            }

            // Only single node to call charon create cluster generate keys
            let kvs = vec![
                Kv::new(
                    "name",
                    format!("compose-{}-{}", conf.num_nodes, conf.num_validators),
                ),
                Kv::new("threshold", conf.threshold.to_string()),
                Kv::new("nodes", conf.num_nodes.to_string()),
                Kv::new("cluster-dir", "/compose"),
                Kv::new(
                    "split-existing-keys",
                    quoted_bool(!conf.split_keys_dir.is_empty()),
                ),
                Kv::new("split-keys-dir", split_keys_dir),
                Kv::new("num-validators", conf.num_validators.to_string()),
                Kv::new("insecure-keys", quoted_bool(conf.insecure_keys)),
                Kv::new("withdrawal-addresses", ZERO_ADDRESS),
                Kv::new("fee-recipient-addresses", ZERO_ADDRESS),
                Kv::new("network", pluto_eth2util::network::GOERLI.name),
            ];

            let node = TmplNode {
                image: conf.image_override(conf.keygen_impl()),
                env_vars: kvs,
                ..TmplNode::default()
            };

            TmplData {
                compose_dir: dir_str,
                charon_image_tag: conf.image_tag.clone(),
                charon_command: CMD_CREATE_CLUSTER.to_string(),
                nodes: vec![node],
                ..TmplData::default()
            }
        }
        KeyGen::Dkg => {
            let nodes = (0..conf.num_nodes)
                .map(|i| TmplNode {
                    env_vars: new_node_envs(i, &conf, None),
                    image: conf.image_override(conf.node_impl(i)),
                    command: CMD_DKG.to_string(),
                    ..TmplNode::default()
                })
                .collect();

            TmplData {
                compose_dir: dir_str,
                charon_image_tag: conf.image_tag.clone(),
                charon_command: "not used".to_string(),
                relay: true,
                nodes,
                ..TmplData::default()
            }
        }
    };

    info!("Creating docker-compose.yml");
    info!("Create keys and cluster lock with: docker compose up");

    conf.step = Step::Locked;
    write_config(dir, &conf)?;

    write_docker_compose(dir, &data)?;

    Ok(data)
}

/// Formats a bool quoted for the compose environment, e.g. `"true"`.
pub(crate) fn quoted_bool(value: bool) -> String {
    format!("\"{value}\"")
}

/// Returns the environment variables for a charon node container: the
/// common flags, then either the DKG flags (config step `defined`) or the
/// run flags, plus the loki/tempo flags when monitoring is on.
pub(crate) fn new_node_envs(index: usize, conf: &Config, vc_type: Option<VcType>) -> Vec<Kv> {
    let mut beacon_mock = false;

    let mut beacon_node = conf.beacon_nodes.as_str();
    if beacon_node == "mock" {
        beacon_mock = true;
        beacon_node = "";
    }

    // The path-less URL form (multiaddrs response) instead of charon-compose's
    // /enr path: pluto's relay parsing roundtrips URLs through a multiaddr,
    // which cannot represent a URL path. Charon supports both forms.
    let p2p_relay_addr = if conf.external_relay.is_empty() {
        "http://relay:3640"
    } else {
        conf.external_relay.as_str()
    };

    // Common config
    let mut kvs = vec![
        Kv::new(
            "private-key-file",
            format!("/compose/node{index}/charon-enr-private-key"),
        ),
        Kv::new("monitoring-address", "0.0.0.0:3620"),
        Kv::new("p2p-external-hostname", format!("node{index}")),
        Kv::new("p2p-tcp-address", "0.0.0.0:3610"),
        Kv::new("p2p-relays", p2p_relay_addr),
        Kv::new("log-level", "debug"),
        Kv::new("log-color", "force"),
        Kv::new("feature-set", conf.feature_set.as_str()),
    ];

    if conf.step == Step::Defined {
        // Define lock config
        kvs.extend([
            Kv::new("data-dir", format!("/compose/node{index}")),
            Kv::new("definition-file", "/compose/cluster-definition.json"),
            Kv::new("insecure-keys", quoted_bool(conf.insecure_keys)),
        ]);

        return kvs;
    }

    // Define run config
    kvs.extend([
        Kv::new(
            "lock-file",
            format!("/compose/node{index}/cluster-lock.json"),
        ),
        Kv::new("validator-api-address", "0.0.0.0:3600"),
        Kv::new("beacon-node-endpoints", beacon_node),
        Kv::new("simnet-beacon_mock", quoted_bool(beacon_mock)),
        Kv::new(
            "simnet-validator-mock",
            quoted_bool(vc_type == Some(VcType::Mock)),
        ),
        Kv::new(
            "simnet-slot-duration",
            go_duration_string(conf.slot_duration),
        ),
        Kv::new(
            "simnet-validator-keys-dir",
            format!("/compose/node{index}/validator_keys"),
        ),
        Kv::new("simnet-beacon-mock-fuzz", quoted_bool(conf.beacon_fuzz)),
        Kv::new(
            "synthetic-block-proposals",
            quoted_bool(conf.synthetic_block_proposals),
        ),
        Kv::new("builder-api", quoted_bool(conf.builder_api)),
    ]);

    // Unlike charon's compose, only point nodes at loki/tempo when the
    // monitoring stack actually runs: failed pushes to absent services are
    // logged as errors, tripping the Error Log Rate alert.
    if conf.monitoring {
        kvs.extend([
            Kv::new("otlp-address", "tempo:4317"),
            Kv::new("otlp-service-name", format!("node{index}")),
            Kv::new("loki-addresses", "http://loki:3100/loki/api/v1/push"),
            Kv::new("loki-service", format!("node{index}")),
        ]);
    }

    kvs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(kvs: &[Kv]) -> Vec<&str> {
        kvs.iter().map(|kv| kv.key.as_str()).collect()
    }

    fn value<'a>(kvs: &'a [Kv], key: &str) -> &'a str {
        kvs.iter()
            .find(|kv| kv.key == key)
            .map(|kv| kv.value.as_str())
            .unwrap_or_else(|| panic!("missing {key}"))
    }

    #[test]
    fn defined_step_uses_dkg_flags() {
        let mut conf = Config::new_default();
        conf.step = Step::Defined;

        let kvs = new_node_envs(2, &conf, None);
        assert_eq!(
            keys(&kvs),
            [
                "private-key-file",
                "monitoring-address",
                "p2p-external-hostname",
                "p2p-tcp-address",
                "p2p-relays",
                "log-level",
                "log-color",
                "feature-set",
                "data-dir",
                "definition-file",
                "insecure-keys",
            ]
        );
        assert_eq!(value(&kvs, "data-dir"), "/compose/node2");
        assert_eq!(value(&kvs, "p2p-relays"), "http://relay:3640");
        assert_eq!(value(&kvs, "insecure-keys"), "\"false\"");
    }

    #[test]
    fn run_step_reflects_config_toggles() {
        let mut conf = Config::new_default();
        conf.step = Step::Locked;
        conf.monitoring = false;
        conf.external_relay = "http://example.org:3640".to_string();
        conf.beacon_nodes = "http://beacon:5052".to_string();

        let kvs = new_node_envs(0, &conf, Some(VcType::Mock));
        assert_eq!(value(&kvs, "p2p-relays"), "http://example.org:3640");
        assert_eq!(value(&kvs, "beacon-node-endpoints"), "http://beacon:5052");
        assert_eq!(value(&kvs, "simnet-beacon_mock"), "\"false\"");
        assert_eq!(value(&kvs, "simnet-validator-mock"), "\"true\"");
        assert_eq!(value(&kvs, "simnet-slot-duration"), "1s");
        assert!(!keys(&kvs).contains(&"otlp-address"));
        assert!(!keys(&kvs).contains(&"loki-addresses"));

        conf.monitoring = true;
        let kvs = new_node_envs(3, &conf, Some(VcType::Teku));
        assert_eq!(value(&kvs, "simnet-validator-mock"), "\"false\"");
        assert_eq!(value(&kvs, "otlp-service-name"), "node3");
        assert_eq!(value(&kvs, "loki-service"), "node3");
    }

    #[test]
    fn lock_rejects_non_defined_step() {
        let conf = Config::new_default();
        let dir = tempfile::tempdir().expect("tempdir");
        let err = lock(dir.path(), conf).expect_err("must fail");
        assert_eq!(
            err.to_string(),
            "compose config not defined, so can't be locked: step=new"
        );
    }

    #[test]
    fn lock_create_maps_split_keys_dir_into_container() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys_dir = dir.path().join("split-keys");
        std::fs::create_dir(&keys_dir).expect("mkdir");

        let mut conf = Config::new_default();
        conf.step = Step::Defined;
        conf.split_keys_dir = keys_dir.to_string_lossy().into_owned();

        let data = lock(dir.path(), conf).expect("lock");
        let kvs = &data.nodes[0].env_vars;
        assert_eq!(value(kvs, "split-existing-keys"), "\"true\"");
        assert_eq!(value(kvs, "split-keys-dir"), "/compose/split-keys");
    }
}
