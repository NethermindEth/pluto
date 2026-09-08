//! Compose cluster configuration (`config.json`).

use std::{fmt, fs, path::Path, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    Result, define::ALERT_RULE_NAMES, error::ComposeError, fsutil::write_file, template::Port,
};

/// Version of the compose config format.
pub const VERSION: &str = "obol/charon/compose/1.0.0";

pub(crate) const CONFIG_FILE: &str = "config.json";

const DEFAULT_IMAGE_TAG: &str = "latest";
const DEFAULT_BEACON_NODE: &str = "mock";
const DEFAULT_NUM_VALS: usize = 1;
const DEFAULT_NUM_NODES: usize = 4;
const DEFAULT_THRESHOLD: usize = 3;
const DEFAULT_FEATURE_SET: &str = "alpha";

pub(crate) const CHARON_IMAGE: &str = "obolnetwork/charon";
const PLUTO_IMAGE: &str = "pluto";

/// Env var holding the path of the charon repo to build `charon:local` from.
pub const CHARON_REPO_ENV: &str = "CHARON_REPO";
/// Env var holding the path of the pluto repo to build `pluto:local` from.
pub const PLUTO_REPO_ENV: &str = "PLUTO_REPO";

pub(crate) const CMD_RUN: &str = "run";
pub(crate) const CMD_UNSAFE_RUN: &str = "[unsafe,run]";
pub(crate) const CMD_DKG: &str = "[dkg,--shutdown-delay=2s]";
pub(crate) const CMD_CREATE_CLUSTER: &str = "[create,cluster]";
pub(crate) const CMD_CREATE_DKG: &str = "[create,dkg]";

/// Ports every charon node exposes; `run` offsets the external side per node.
pub const CHARON_PORTS: [Port; 4] = [
    Port {
        external: 3600,
        internal: 3600,
    },
    Port {
        external: 3610,
        internal: 3610,
    },
    Port {
        external: 3620,
        internal: 3620,
    },
    Port {
        external: 3630,
        internal: 3630,
    },
];

/// Validator client type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VcType {
    /// Charon's built-in validator mock.
    Mock,
    /// Consensys Teku.
    Teku,
    /// Sigma Prime Lighthouse.
    Lighthouse,
    /// Attestant Vouch.
    Vouch,
    /// ChainSafe Lodestar.
    Lodestar,
}

impl VcType {
    /// The lowercase name used in configs and compose labels.
    pub fn as_str(self) -> &'static str {
        match self {
            VcType::Mock => "mock",
            VcType::Teku => "teku",
            VcType::Lighthouse => "lighthouse",
            VcType::Vouch => "vouch",
            VcType::Lodestar => "lodestar",
        }
    }
}

impl fmt::Display for VcType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Key generation process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyGen {
    /// Distributed key generation between the nodes.
    Dkg,
    /// `charon create cluster` on a single node.
    #[default]
    Create,
}

impl KeyGen {
    /// The lowercase name used in configs.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyGen::Dkg => "dkg",
            KeyGen::Create => "create",
        }
    }
}

impl fmt::Display for KeyGen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Node implementation to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeImpl {
    /// The reference Go implementation.
    Charon,
    /// This Rust implementation.
    Pluto,
}

impl NodeImpl {
    /// The lowercase name used in configs.
    pub fn as_str(self) -> &'static str {
        match self {
            NodeImpl::Charon => "charon",
            NodeImpl::Pluto => "pluto",
        }
    }

    /// Env var naming the repo a local image of this implementation is built
    /// from.
    pub fn repo_env(self) -> &'static str {
        match self {
            NodeImpl::Charon => CHARON_REPO_ENV,
            NodeImpl::Pluto => PLUTO_REPO_ENV,
        }
    }

    /// Image reference a local build of this implementation is tagged with.
    pub fn local_image(self) -> String {
        match self {
            NodeImpl::Charon => format!("{CHARON_IMAGE}:local"),
            NodeImpl::Pluto => format!("{PLUTO_IMAGE}:local"),
        }
    }
}

impl fmt::Display for NodeImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Compose workflow step.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Step {
    /// Config written, nothing generated yet.
    #[default]
    New,
    /// Cluster definition compose file generated.
    Defined,
    /// Cluster lock compose file generated.
    Locked,
}

impl Step {
    /// The lowercase name used in configs.
    pub fn as_str(self) -> &'static str {
        match self {
            Step::New => "new",
            Step::Defined => "defined",
            Step::Locked => "locked",
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Serde adaptor that writes an empty list as `null` (a nil slice) and reads
/// `null` back as an empty list.
pub(crate) mod nullable_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<T: Serialize, S: Serializer>(
        items: &[T],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if items.is_empty() {
            serializer.serialize_none()
        } else {
            items.serialize(serializer)
        }
    }

    pub(crate) fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<T>, D::Error> {
        Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
    }
}

/// Serde adaptor for the optional keygen implementation: absent is the empty
/// string.
mod keygen_impl {
    use serde::{Deserialize, Deserializer, Serializer, de::IntoDeserializer as _};

    use super::NodeImpl;

    pub(super) fn serialize<S: Serializer>(
        value: &Option<NodeImpl>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(value.map_or("", NodeImpl::as_str))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<NodeImpl>, D::Error> {
        let name = String::deserialize(deserializer)?;
        if name.is_empty() {
            return Ok(None);
        }

        NodeImpl::deserialize(name.into_deserializer()).map(Some)
    }
}

/// Serde adaptor storing a duration as Go `time.Duration` does: an integer
/// count of nanoseconds.
mod nanos {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer, de, ser};

    pub(super) fn serialize<S: Serializer>(
        value: &Duration,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let nanos = i64::try_from(value.as_nanos()).map_err(ser::Error::custom)?;
        serializer.serialize_i64(nanos)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Duration, D::Error> {
        let nanos = i64::deserialize(deserializer)?;
        let nanos = u64::try_from(nanos)
            .map_err(|_| de::Error::custom(format!("negative duration: {nanos}")))?;

        Ok(Duration::from_nanos(nanos))
    }
}

/// Compose cluster configuration, persisted as `config.json` in the compose
/// directory.
///
/// Fields missing from a hand-edited file take their zero value, except the
/// enum-typed `step` and `key_gen`, which default to `new` and `create`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Config format version, see [`VERSION`].
    pub version: String,
    /// Current workflow step.
    pub step: Step,
    /// Number of charon/pluto nodes in the cluster.
    pub num_nodes: usize,
    /// Signature threshold of the cluster.
    pub threshold: usize,
    /// Number of distributed validators.
    pub num_validators: usize,
    /// Docker image tag of the charon image.
    pub image_tag: String,
    /// Build the charon image locally from `CHARON_REPO`.
    pub build_local: bool,
    /// Implementation per node index, cycled when shorter than `num_nodes`.
    /// Empty means every node runs charon.
    #[serde(with = "nullable_vec")]
    pub node_impls: Vec<NodeImpl>,
    /// Implementation running the key generation container. Absent means the
    /// implementation of node 0.
    #[serde(rename = "keygen_impl", with = "keygen_impl")]
    pub key_gen_impl: Option<NodeImpl>,
    /// Docker image tag of the pluto image; `local` builds it from
    /// `PLUTO_REPO`.
    pub pluto_image_tag: String,
    /// Key generation process.
    pub key_gen: KeyGen,
    /// Directory of existing validator keys to split, relative to the compose
    /// directory. Empty generates new keys.
    pub split_keys_dir: String,
    /// Beacon node endpoint(s), or `mock` for the built-in beacon mock.
    pub beacon_nodes: String,
    /// External relay address; empty runs a relay container.
    pub external_relay: String,
    /// Validator client per node index, cycled when shorter than `num_nodes`.
    #[serde(rename = "validator_clients", with = "nullable_vec")]
    pub vcs: Vec<VcType>,
    /// Charon feature set to enable.
    pub feature_set: String,
    /// Do not publish node and prometheus ports on the host.
    pub disable_monitoring_ports: bool,
    /// Use insecure (deterministic) validator keys.
    pub insecure_keys: bool,
    /// Simnet slot duration.
    #[serde(with = "nanos")]
    pub slot_duration: Duration,
    /// Fuzz the beacon mock.
    #[serde(rename = "beacon-fuzz")]
    pub beacon_fuzz: bool,
    /// Fuzz p2p messages sent by node 0.
    #[serde(rename = "p2p-fuzz")]
    pub p2p_fuzz: bool,
    /// Enable synthetic block proposals.
    pub synthetic_block_proposals: bool,
    /// Run the grafana/tempo/loki monitoring stack.
    pub monitoring: bool,
    /// Enable the builder API.
    pub builder_api: bool,
    /// Prometheus jobs exempt from the behavioural alert rules.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alert_exclude_jobs: Vec<String>,
    /// Alert rules to leave out of `rules.yml`, by name.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alert_disable_rules: Vec<String>,
}

impl Config {
    /// Returns the default config: four charon nodes with threshold three,
    /// one validator, `create` key generation, the beacon mock, two lighthouse
    /// validator clients plus a mock, monitoring on and a one second slot.
    pub fn new_default() -> Self {
        Self {
            version: VERSION.to_string(),
            num_nodes: DEFAULT_NUM_NODES,
            threshold: DEFAULT_THRESHOLD,
            num_validators: DEFAULT_NUM_VALS,
            image_tag: DEFAULT_IMAGE_TAG.to_string(),
            node_impls: vec![NodeImpl::Charon],
            pluto_image_tag: "local".to_string(),
            vcs: vec![VcType::Lighthouse, VcType::Lighthouse, VcType::Mock],
            key_gen: KeyGen::Create,
            beacon_nodes: DEFAULT_BEACON_NODE.to_string(),
            step: Step::New,
            feature_set: DEFAULT_FEATURE_SET.to_string(),
            slot_duration: Duration::from_secs(1),
            synthetic_block_proposals: true,
            monitoring: true,
            ..Self::default()
        }
    }

    /// Checks the config for values the generator cannot act on.
    pub fn validate(&self) -> Result<()> {
        for rule in &self.alert_disable_rules {
            if !ALERT_RULE_NAMES.contains(&rule.as_str()) {
                return Err(ComposeError::UnknownAlertRule { rule: rule.clone() });
            }
        }

        Ok(())
    }

    /// Returns the implementation of the node at `index`, cycling through
    /// `node_impls`; charon when none are configured.
    pub fn node_impl(&self, index: usize) -> NodeImpl {
        self.node_impls
            .iter()
            .cycle()
            .nth(index)
            .copied()
            .unwrap_or(NodeImpl::Charon)
    }

    /// Returns the implementation that runs key generation: `key_gen_impl`
    /// when set, otherwise node 0's implementation.
    pub fn keygen_impl(&self) -> NodeImpl {
        self.key_gen_impl.unwrap_or_else(|| self.node_impl(0))
    }

    /// Returns the per-service image override for the compose template: the
    /// pluto image for pluto, empty for charon (which uses the shared base).
    pub fn image_override(&self, node_impl: NodeImpl) -> String {
        match node_impl {
            NodeImpl::Pluto => {
                let tag = &self.pluto_image_tag;
                format!("{PLUTO_IMAGE}:{tag}")
            }
            NodeImpl::Charon => String::new(),
        }
    }

    /// Whether any node or the keygen container runs pluto.
    pub fn uses_pluto(&self) -> bool {
        (0..self.num_nodes).any(|i| self.node_impl(i) == NodeImpl::Pluto)
            || self.keygen_impl() == NodeImpl::Pluto
    }
}

/// Serialises `value` as JSON indented by one space, the layout Go's
/// `json.MarshalIndent(v, "", " ")` produces and the golden files record.
pub(crate) fn marshal_indent<T: Serialize>(value: &T) -> serde_json::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut buf, formatter);
    value.serialize(&mut serializer)?;

    Ok(buf)
}

/// Validates `conf` and writes it to `config.json` in `dir`.
pub fn write_config(dir: impl AsRef<Path>, conf: &Config) -> Result<()> {
    conf.validate()?;

    let json = marshal_indent(conf).map_err(ComposeError::MarshalConfig)?;

    write_file(dir.as_ref().join(CONFIG_FILE), json, 0o755)
        .map_err(ComposeError::io("write config"))
}

/// Loads and validates `config.json` from `dir`.
pub fn load_config(dir: impl AsRef<Path>) -> Result<Config> {
    let bytes =
        fs::read(dir.as_ref().join(CONFIG_FILE)).map_err(ComposeError::io("load config"))?;

    let conf: Config = serde_json::from_slice(&bytes).map_err(ComposeError::UnmarshalConfig)?;
    conf.validate()?;

    Ok(conf)
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case(&[NodeImpl::Pluto], 3, NodeImpl::Pluto ; "single_cycles")]
    #[test_case(&[NodeImpl::Charon, NodeImpl::Pluto], 2, NodeImpl::Charon ; "mixed_wraps")]
    #[test_case(&[], 1, NodeImpl::Charon ; "empty_is_charon")]
    fn node_impl_cycles(impls: &[NodeImpl], index: usize, want: NodeImpl) {
        let conf = Config {
            node_impls: impls.to_vec(),
            ..Config::new_default()
        };
        assert_eq!(conf.node_impl(index), want);
    }

    #[test]
    fn config_roundtrips_through_json() {
        let mut conf = Config::new_default();
        conf.node_impls = vec![NodeImpl::Charon, NodeImpl::Pluto];
        conf.key_gen_impl = Some(NodeImpl::Pluto);
        conf.alert_exclude_jobs = vec!["node0".to_string()];
        conf.alert_disable_rules = vec!["Pluto Down".to_string()];

        let json = marshal_indent(&conf).expect("marshal");
        let back: Config = serde_json::from_slice(&json).expect("unmarshal");
        assert_eq!(back, conf);
    }

    #[test]
    fn config_validate_rejects_unknown_impl() {
        // Enum-typed impls cannot hold unknown names; only a hand-edited config
        // can carry one.
        let dir = tempfile::tempdir().expect("tempdir");
        let bad_json = r#"{"version":"obol/charon/compose/1.0.0","node_impls":["geth"]}"#;
        fs::write(dir.path().join(CONFIG_FILE), bad_json).expect("write");
        let err = load_config(dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("unknown variant `geth`"), "{err}");

        let dir = tempfile::tempdir().expect("tempdir");
        let bad_json = r#"{"version":"obol/charon/compose/1.0.0","keygen_impl":"plutoo"}"#;
        fs::write(dir.path().join(CONFIG_FILE), bad_json).expect("write");
        let err = load_config(dir.path()).expect_err("must fail");
        assert!(
            err.to_string().contains("unknown variant `plutoo`"),
            "{err}"
        );

        // The happy path still validates.
        let mut conf = Config::new_default();
        conf.node_impls = vec![NodeImpl::Charon, NodeImpl::Pluto];
        conf.key_gen_impl = Some(NodeImpl::Pluto);
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(dir.path(), &conf).expect("write config");
        assert_eq!(load_config(dir.path()).expect("load config"), conf);
    }
}
