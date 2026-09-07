//! Compose cluster configuration (`config.json`).

use std::{fmt, fs, path::Path, time::Duration};

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    Result, define::ALERT_RULE_NAMES, error::ComposeError, fsutil::write_file, template::Port,
};

/// Version of the compose config format.
pub const VERSION: &str = "obol/charon/compose/1.0.0";

pub(crate) const CONFIG_FILE: &str = "config.json";

const DEFAULT_IMAGE_TAG: &str = "latest";
const DEFAULT_BEACON_NODE: &str = "mock";
const DEFAULT_KEY_GEN: KeyGen = KeyGen::Create;
const DEFAULT_NUM_VALS: usize = 1;
const DEFAULT_NUM_NODES: usize = 4;
const DEFAULT_THRESHOLD: usize = 3;
const DEFAULT_FEATURE_SET: &str = "alpha";

const CHARON_IMAGE: &str = "obolnetwork/charon";
const PLUTO_IMAGE: &str = "pluto";

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyGen {
    /// Distributed key generation between the nodes.
    Dkg,
    /// `charon create cluster` on a single node.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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

    fn parse(s: &str) -> Option<Self> {
        match s {
            "charon" => Some(NodeImpl::Charon),
            "pluto" => Some(NodeImpl::Pluto),
            _ => None,
        }
    }
}

impl fmt::Display for NodeImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NodeImpl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        NodeImpl::parse(&name).ok_or_else(|| {
            de::Error::custom(format!(
                "unknown node implementation; must be charon or pluto: impl={name}"
            ))
        })
    }
}

/// Compose workflow step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Step {
    /// Config written, nothing generated yet.
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
/// string, and unknown names are rejected with the keygen-specific message.
mod keygen_impl {
    use serde::{Deserialize, Deserializer, Serializer, de};

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

        NodeImpl::parse(&name).map(Some).ok_or_else(|| {
            de::Error::custom(format!(
                "unknown keygen implementation; must be charon or pluto: impl={name}"
            ))
        })
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for Config {
    fn default() -> Self {
        Self {
            version: String::new(),
            step: Step::New,
            num_nodes: 0,
            threshold: 0,
            num_validators: 0,
            image_tag: String::new(),
            build_local: false,
            node_impls: Vec::new(),
            key_gen_impl: None,
            pluto_image_tag: String::new(),
            key_gen: KeyGen::Create,
            split_keys_dir: String::new(),
            beacon_nodes: String::new(),
            external_relay: String::new(),
            vcs: Vec::new(),
            feature_set: String::new(),
            disable_monitoring_ports: false,
            insecure_keys: false,
            slot_duration: Duration::ZERO,
            beacon_fuzz: false,
            p2p_fuzz: false,
            synthetic_block_proposals: false,
            monitoring: false,
            builder_api: false,
            alert_exclude_jobs: Vec::new(),
            alert_disable_rules: Vec::new(),
        }
    }
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
            key_gen: DEFAULT_KEY_GEN,
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
        index
            .checked_rem(self.node_impls.len())
            .and_then(|i| self.node_impls.get(i))
            .copied()
            .unwrap_or(NodeImpl::Charon)
    }

    /// Returns the implementation that runs key generation: `key_gen_impl`
    /// when set, otherwise node 0's implementation.
    pub fn keygen_impl(&self) -> NodeImpl {
        self.key_gen_impl.unwrap_or_else(|| self.node_impl(0))
    }

    /// Returns the full docker image reference for an implementation.
    pub fn impl_image(&self, node_impl: NodeImpl) -> String {
        match node_impl {
            NodeImpl::Pluto => {
                let tag = &self.pluto_image_tag;
                format!("{PLUTO_IMAGE}:{tag}")
            }
            NodeImpl::Charon => {
                let tag = &self.image_tag;
                format!("{CHARON_IMAGE}:{tag}")
            }
        }
    }

    /// Returns the per-service image override for the compose template: the
    /// pluto image for pluto, empty for charon (which uses the shared base).
    pub fn image_override(&self, node_impl: NodeImpl) -> String {
        match node_impl {
            NodeImpl::Pluto => self.impl_image(node_impl),
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

    write_file(dir.as_ref().join(CONFIG_FILE), json, 0o755).map_err(ComposeError::WriteConfig)
}

/// Loads and validates `config.json` from `dir`.
pub fn load_config(dir: impl AsRef<Path>) -> Result<Config> {
    let bytes = fs::read(dir.as_ref().join(CONFIG_FILE)).map_err(ComposeError::LoadConfig)?;

    let conf: Config = serde_json::from_slice(&bytes).map_err(ComposeError::UnmarshalConfig)?;
    conf.validate()?;

    Ok(conf)
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case(&[], 0, NodeImpl::Charon ; "empty_defaults_to_charon")]
    #[test_case(&[NodeImpl::Pluto], 3, NodeImpl::Pluto ; "single_cycles")]
    #[test_case(&[NodeImpl::Charon, NodeImpl::Pluto], 0, NodeImpl::Charon ; "mixed_first")]
    #[test_case(&[NodeImpl::Charon, NodeImpl::Pluto], 1, NodeImpl::Pluto ; "mixed_second")]
    #[test_case(&[NodeImpl::Charon, NodeImpl::Pluto], 2, NodeImpl::Charon ; "mixed_wraps")]
    fn node_impl_cycles(impls: &[NodeImpl], index: usize, want: NodeImpl) {
        let conf = Config {
            node_impls: impls.to_vec(),
            ..Config::new_default()
        };
        assert_eq!(conf.node_impl(index), want);
    }

    #[test]
    fn keygen_impl_falls_back_to_node0() {
        let mut conf = Config::new_default();
        conf.node_impls = vec![NodeImpl::Pluto, NodeImpl::Charon];
        assert_eq!(conf.keygen_impl(), NodeImpl::Pluto);

        conf.key_gen_impl = Some(NodeImpl::Charon);
        assert_eq!(conf.keygen_impl(), NodeImpl::Charon);
    }

    #[test]
    fn images() {
        let conf = Config {
            image_tag: "v1".to_string(),
            pluto_image_tag: "dev".to_string(),
            ..Config::new_default()
        };
        assert_eq!(conf.impl_image(NodeImpl::Charon), "obolnetwork/charon:v1");
        assert_eq!(conf.impl_image(NodeImpl::Pluto), "pluto:dev");
        assert_eq!(conf.image_override(NodeImpl::Charon), "");
        assert_eq!(conf.image_override(NodeImpl::Pluto), "pluto:dev");
    }

    #[test]
    fn uses_pluto_checks_nodes_and_keygen() {
        let mut conf = Config::new_default();
        assert!(!conf.uses_pluto());

        conf.key_gen_impl = Some(NodeImpl::Pluto);
        assert!(conf.uses_pluto());

        conf.key_gen_impl = None;
        conf.node_impls = vec![
            NodeImpl::Charon,
            NodeImpl::Charon,
            NodeImpl::Charon,
            NodeImpl::Pluto,
        ];
        assert!(conf.uses_pluto());

        // A pluto entry beyond num_nodes is never reached.
        conf.num_nodes = 3;
        assert!(!conf.uses_pluto());
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
    fn missing_fields_take_zero_values() {
        let conf: Config =
            serde_json::from_str(r#"{"version":"obol/charon/compose/1.0.0"}"#).expect("unmarshal");
        assert_eq!(conf.version, VERSION);
        assert_eq!(conf.num_nodes, 0);
        assert!(conf.node_impls.is_empty());
        assert_eq!(conf.key_gen_impl, None);
        assert_eq!(conf.slot_duration, Duration::ZERO);
    }

    #[test]
    fn null_lists_load_as_empty() {
        let conf: Config = serde_json::from_str(r#"{"node_impls":null,"validator_clients":null}"#)
            .expect("unmarshal");
        assert!(conf.node_impls.is_empty());
        assert!(conf.vcs.is_empty());
    }

    #[test]
    fn empty_lists_serialize_as_null() {
        let conf = Config {
            node_impls: Vec::new(),
            vcs: Vec::new(),
            ..Config::new_default()
        };
        let json: serde_json::Value =
            serde_json::from_slice(&marshal_indent(&conf).expect("marshal")).expect("parse");
        assert_eq!(json["node_impls"], serde_json::Value::Null);
        assert_eq!(json["validator_clients"], serde_json::Value::Null);
        assert_eq!(
            json["keygen_impl"],
            serde_json::Value::String(String::new())
        );
        assert!(json.get("alert_exclude_jobs").is_none());
        assert!(json.get("alert_disable_rules").is_none());
    }

    #[test]
    fn config_validate_rejects_unknown_impl() {
        // Enum-typed implementations cannot hold unknown names in memory, so
        // the write-side assertions have no Rust counterpart; loading a
        // hand-edited config with a bad impl still fails.
        let dir = tempfile::tempdir().expect("tempdir");
        let bad_json = r#"{"version":"obol/charon/compose/1.0.0","node_impls":["geth"]}"#;
        fs::write(dir.path().join(CONFIG_FILE), bad_json).expect("write");
        let err = load_config(dir.path()).expect_err("must fail");
        assert!(
            err.to_string().contains("unknown node implementation"),
            "{err}"
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let bad_json = r#"{"version":"obol/charon/compose/1.0.0","keygen_impl":"plutoo"}"#;
        fs::write(dir.path().join(CONFIG_FILE), bad_json).expect("write");
        let err = load_config(dir.path()).expect_err("must fail");
        assert!(
            err.to_string().contains("unknown keygen implementation"),
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

    #[test]
    fn load_config_missing_file_keeps_not_found_kind() {
        let dir = tempfile::tempdir().expect("tempdir");
        match load_config(dir.path()) {
            Err(ComposeError::LoadConfig(err)) => {
                assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
