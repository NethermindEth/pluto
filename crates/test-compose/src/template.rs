//! Data model for `docker-compose.yml` and the writer that renders it.

use std::path::Path;

use serde::Serialize;

use crate::{
    Result,
    config::{CHARON_IMAGE, nullable_vec},
    error::ComposeError,
    fsutil::write_file,
};

/// Everything `docker-compose.yml` is rendered from.
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

/// Writes `docker-compose.yml` for `data` into `dir`.
pub fn write_docker_compose(dir: impl AsRef<Path>, data: &TmplData) -> Result<()> {
    write_file(
        dir.as_ref().join("docker-compose.yml"),
        compose_yaml(data),
        0o755,
    )
    .map_err(ComposeError::io("write docker-compose.yml"))
}

/// Renders the compose file: a `node-base` anchor shared by the nodes and the
/// relay, one service per node and validator client, then the optional
/// alerting (curl + prometheus) and monitoring (grafana, tempo, loki) stacks.
fn compose_yaml(data: &TmplData) -> String {
    let mut y = Yaml::default();

    y.line("x-node-base: &node-base");
    let tag = &data.charon_image_tag;
    y.line(format!("  image: {CHARON_IMAGE}:{tag}"));
    y.opt("  entrypoint: ", &data.charon_entrypoint);
    y.line(format!("  command: {}", data.charon_command));
    y.line("  networks: [compose]");
    y.line(format!("  volumes: [{}:/compose]", data.compose_dir));
    if data.relay {
        y.line("  depends_on: [relay]");
    }
    y.line("");
    y.line("services:");

    for (i, node) in data.nodes.iter().enumerate() {
        y.line(format!("  node{i}:"));
        y.line("    <<: *node-base");
        y.line(format!("    container_name: node{i}"));
        y.opt("    image: ", &node.image);
        y.opt("    entrypoint: ", &node.entrypoint);
        y.opt("    command: ", &node.command);
        if !node.env_vars.is_empty() {
            y.line("    environment:");
            for kv in &node.env_vars {
                y.line(format!("      CHARON_{}: {}", kv.env_key(), kv.value));
            }
        }
        y.ports(&node.ports);
        y.line("");
    }

    if data.relay {
        y.line(RELAY_SERVICE);
    }

    for (i, vc) in data.vcs.iter().enumerate() {
        if vc.label.is_empty() {
            continue;
        }
        y.line(format!("  vc{i}-{}:", vc.label));
        y.line(format!("    container_name: vc{i}-{}", vc.label));
        y.opt("    build: ", &vc.build);
        y.opt("    image: ", &vc.image);
        y.opt("    command: ", &vc.command);
        y.line("    networks: [compose]");
        y.line(format!("    depends_on: [node{i}]"));
        y.line("    environment:");
        y.line(format!("      NODE: node{i}"));
        y.line("    volumes:");
        y.line("      - .:/compose");
        y.line("");
    }

    if data.alerting {
        y.line(CURL_SERVICE);
        y.line("  prometheus:");
        y.line("    container_name: prometheus");
        y.line("    image: prom/prometheus:${PROMETHEUS_VERSION:-v2.50.1}");
        if data.monitoring_ports {
            y.line("    ports:");
            y.line("      - \"9090:9090\"");
        }
        y.line("    networks: [compose]");
        y.line("    volumes:");
        y.line("      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml");
        y.line("      - ./prometheus/rules.yml:/etc/prometheus/rules.yml");
        y.line("");
    }

    if data.monitoring {
        y.line("  grafana:");
        y.line("    container_name: grafana");
        y.line("    image: grafana/grafana:${GRAFANA_VERSION:-10.4.2}");
        if data.monitoring_ports {
            y.line("    ports:");
            y.line("      - \"3000:3000\"");
        }
        y.line(GRAFANA_TAIL);
        y.line(TEMPO_LOKI_SERVICES);
    }

    y.line("networks:");
    y.line("  compose:");
    y.0
}

/// Line-oriented YAML output; every value is inserted verbatim.
#[derive(Default)]
struct Yaml(String);

impl Yaml {
    fn line(&mut self, s: impl AsRef<str>) {
        self.0.push_str(s.as_ref());
        self.0.push('\n');
    }

    /// `prefix` + `value` on one line, or nothing when the value is empty.
    fn opt(&mut self, prefix: &str, value: &str) {
        if !value.is_empty() {
            self.line(format!("{prefix}{value}"));
        }
    }

    fn ports(&mut self, ports: &[Port]) {
        if ports.is_empty() {
            return;
        }
        self.line("    ports:");
        for port in ports {
            self.line(format!("      - \"{}:{}\"", port.external, port.internal));
        }
    }
}

const RELAY_SERVICE: &str = r#"  relay:
    <<: *node-base
    container_name: relay
    command: relay
    depends_on: []
    environment:
      CHARON_HTTP_ADDRESS: 0.0.0.0:3640
      CHARON_MONITORING_ADDRESS: 0.0.0.0:3620
      CHARON_DATA_DIR: /compose/relay
      CHARON_P2P_RELAYS: ""
      CHARON_P2P_EXTERNAL_HOSTNAME: relay
      CHARON_P2P_TCP_ADDRESS: 0.0.0.0:3610
      CHARON_P2P_UDP_ADDRESS: 0.0.0.0:3630
      CHARON_P2P_ADVERTISE_PRIVATE_ADDRESSES: "true"
      CHARON_LOKI_ADDRESS: http://loki:3100/loki/api/v1/push
"#;

const CURL_SERVICE: &str = r#"  curl:
    container_name: curl
    # Can be used to curl services; e.g. docker compose exec curl curl http://prometheus:9090/api/v1/rules\?type\=alert
    image: curlimages/curl:8.21.0
    command: sleep 1d
    networks: [compose]
"#;

const GRAFANA_TAIL: &str = r#"    networks: [compose]
    volumes:
      - ./grafana/datasource.yml:/etc/grafana/provisioning/datasources/datasource.yml
      - ./grafana/dashboards.yml:/etc/grafana/provisioning/dashboards/datasource.yml
      - ./grafana/notifiers.yml:/etc/grafana/provisioning/notifiers/notifiers.yml
      - ./grafana/grafana.ini:/etc/grafana/grafana.ini:ro
      - ./grafana/dash_charon_overview.json:/etc/dashboards/dash_charon_overview.json
      - ./grafana/dash_duty_details.json:/etc/dashboards/dash_duty_details.json
      - ./grafana/dash_alerts.json:/etc/dashboards/dash_alerts.json
"#;

const TEMPO_LOKI_SERVICES: &str = r#"  tempo:
    container_name: tempo
    image: grafana/tempo:${TEMPO_VERSION:-2.7.1}
    networks: [compose]
    user: ":"
    command: -config.file=/opt/tempo/tempo.yaml
    volumes:
      - ./tempo:/opt/tempo

  loki:
    container_name: loki
    image: grafana/loki:${LOKI_VERSION:-2.8.2}
    networks: [compose]
    user: ":"
    command: -config.file=/opt/loki/loki.yml
    volumes:
      - ./loki:/opt/loki
"#;
