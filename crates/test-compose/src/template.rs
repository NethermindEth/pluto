//! Template data for `docker-compose.yml` and its renderer.

use std::path::Path;

use serde::Serialize;

use crate::{
    Result,
    config::nullable_vec,
    error::ComposeError,
    fsutil::write_file,
    gotmpl::{Template, Value},
};

/// The bundled docker-compose template.
const COMPOSE_TEMPLATE: &str = include_str!("../docker-compose.template");

/// Root data of the docker-compose template.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TmplData {
    /// Host directory mounted as `/compose` in every container.
    pub compose_dir: String,
    /// Tag of the shared `obolnetwork/charon` base image.
    pub charon_image_tag: String,
    /// Entrypoint override for the node base service; empty keeps the image's.
    pub charon_entrypoint: String,
    /// Command for the node base service.
    pub charon_command: String,
    /// Node services.
    #[serde(with = "nullable_vec")]
    pub nodes: Vec<TmplNode>,
    /// Validator client services, one per node.
    #[serde(rename = "VCs", with = "nullable_vec")]
    pub vcs: Vec<TmplVc>,
    /// Run the relay service.
    pub relay: bool,
    /// Run the grafana/tempo/loki stack.
    pub monitoring: bool,
    /// Run prometheus and the curl helper.
    pub alerting: bool,
    /// Publish the prometheus port on the host.
    pub monitoring_ports: bool,
}

/// A validator client service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TmplVc {
    /// Service name suffix; empty renders no service.
    pub label: String,
    /// Docker image; empty when built from `build`.
    pub image: String,
    /// Build context under `static/`; empty when using `image`.
    pub build: String,
    /// Command override.
    pub command: String,
    /// Published ports.
    #[serde(with = "nullable_vec")]
    pub ports: Vec<Port>,
}

/// A node service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TmplNode {
    /// Image override; empty inherits the node base image.
    pub image: String,
    /// Entrypoint override.
    pub entrypoint: String,
    /// Command override.
    pub command: String,
    /// Environment variables, rendered as `CHARON_<KEY>`.
    #[serde(with = "nullable_vec")]
    pub env_vars: Vec<Kv>,
    /// Published ports.
    #[serde(with = "nullable_vec")]
    pub ports: Vec<Port>,
}

/// A charon flag and its value, rendered as an environment variable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Kv {
    /// Flag name, e.g. `p2p-tcp-address`.
    pub key: String,
    /// Flag value.
    pub value: String,
}

impl Kv {
    /// Builds a key/value pair.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    /// The environment variable form of the key: upper-cased with dashes
    /// replaced by underscores, e.g. `P2P_TCP_ADDRESS`.
    pub fn env_key(&self) -> String {
        self.key.to_uppercase().replace('-', "_")
    }
}

/// A published port mapping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Port {
    /// Host port.
    pub external: u32,
    /// Container port.
    pub internal: u32,
}

impl From<&Port> for Value {
    fn from(port: &Port) -> Self {
        Value::object([
            ("External", Value::Int(i64::from(port.external))),
            ("Internal", Value::Int(i64::from(port.internal))),
        ])
    }
}

impl From<&Kv> for Value {
    fn from(kv: &Kv) -> Self {
        Value::object([
            ("Key", Value::str(&kv.key)),
            ("Value", Value::str(&kv.value)),
            ("EnvKey", Value::str(kv.env_key())),
        ])
    }
}

impl From<&TmplNode> for Value {
    fn from(node: &TmplNode) -> Self {
        Value::object([
            ("Image", Value::str(&node.image)),
            ("Entrypoint", Value::str(&node.entrypoint)),
            ("Command", Value::str(&node.command)),
            (
                "EnvVars",
                Value::List(node.env_vars.iter().map(Value::from).collect()),
            ),
            (
                "Ports",
                Value::List(node.ports.iter().map(Value::from).collect()),
            ),
        ])
    }
}

impl From<&TmplVc> for Value {
    fn from(vc: &TmplVc) -> Self {
        Value::object([
            ("Label", Value::str(&vc.label)),
            ("Image", Value::str(&vc.image)),
            ("Build", Value::str(&vc.build)),
            ("Command", Value::str(&vc.command)),
            (
                "Ports",
                Value::List(vc.ports.iter().map(Value::from).collect()),
            ),
        ])
    }
}

impl From<&TmplData> for Value {
    fn from(data: &TmplData) -> Self {
        Value::object([
            ("ComposeDir", Value::str(&data.compose_dir)),
            ("CharonImageTag", Value::str(&data.charon_image_tag)),
            ("CharonEntrypoint", Value::str(&data.charon_entrypoint)),
            ("CharonCommand", Value::str(&data.charon_command)),
            (
                "Nodes",
                Value::List(data.nodes.iter().map(Value::from).collect()),
            ),
            (
                "VCs",
                Value::List(data.vcs.iter().map(Value::from).collect()),
            ),
            ("Relay", Value::Bool(data.relay)),
            ("Monitoring", Value::Bool(data.monitoring)),
            ("Alerting", Value::Bool(data.alerting)),
            ("MonitoringPorts", Value::Bool(data.monitoring_ports)),
        ])
    }
}

/// Renders the bundled template with `data` and writes `docker-compose.yml`
/// into `dir`.
pub fn write_docker_compose(dir: impl AsRef<Path>, data: &TmplData) -> Result<()> {
    let template = Template::parse(COMPOSE_TEMPLATE).map_err(ComposeError::NewTemplate)?;
    let rendered = template
        .execute(&Value::from(data))
        .map_err(ComposeError::ExecTemplate)?;

    write_file(dir.as_ref().join("docker-compose.yml"), rendered, 0o755)
        .map_err(ComposeError::WriteDockerCompose)
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case("p2p-tcp-address", "P2P_TCP_ADDRESS" ; "dashes")]
    #[test_case("simnet-beacon_mock", "SIMNET_BEACON_MOCK" ; "mixed_separators")]
    #[test_case("name", "NAME" ; "plain")]
    fn env_key(key: &str, want: &str) {
        assert_eq!(Kv::new(key, "").env_key(), want);
    }

    #[test]
    fn bundled_template_parses() {
        Template::parse(COMPOSE_TEMPLATE).expect("template must parse");
    }
}
