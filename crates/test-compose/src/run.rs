//! Cluster run step: node, validator client and monitoring services.

use std::path::Path;

use tracing::info;

use crate::{
    Result,
    config::{CHARON_PORTS, CMD_RUN, CMD_UNSAFE_RUN, Config, Step, VcType},
    error::ComposeError,
    gotmpl::{Template, Value},
    lock::{new_node_envs, quoted_bool},
    template::{Kv, TmplData, TmplNode, TmplVc, write_docker_compose},
};

/// Command template for the teku validator client; rendered per node with
/// its index, keystore pairs and the builder API toggle.
const TEKU_COMMAND: &str = r#"|
      validator-client
      --network=auto
      --beacon-node-api-endpoint="http://node{{.NodeIdx}}:3600"
      {{range .TekuKeys}}--validator-keys="{{.}}"
      {{end -}}
      --validators-proposer-default-fee-recipient="0x0000000000000000000000000000000000000000"
      --validators-proposer-blinded-blocks-enabled={{.BuilderAPI}}"#;

/// Writes the `docker-compose.yml` that runs the cluster: one node service
/// per configured node with its validator client, the relay, prometheus and
/// (when enabled) the monitoring stack.
///
/// Validator client types cycle through `conf.vcs`; node ports are published
/// on the host offset by 10000 per node unless monitoring ports are
/// disabled. With `p2p_fuzz` node 0 fuzzes its p2p messages and the nodes
/// run `charon unsafe run`.
pub fn run(dir: impl AsRef<Path>, conf: Config) -> Result<TmplData> {
    let dir = dir.as_ref();

    if conf.step != Step::Locked {
        return Err(ComposeError::NotLocked { step: conf.step });
    }

    if conf.vcs.is_empty() {
        return Err(ComposeError::NoValidatorClients);
    }

    let mut nodes = Vec::with_capacity(conf.num_nodes);
    let mut vcs = Vec::with_capacity(conf.num_nodes);

    for i in 0..conf.num_nodes {
        let typ = i
            .checked_rem(conf.vcs.len())
            .and_then(|idx| conf.vcs.get(idx))
            .copied()
            .ok_or(ComposeError::NoValidatorClients)?;

        vcs.push(get_vc(
            typ,
            i,
            conf.num_validators,
            conf.insecure_keys,
            conf.builder_api,
        )?);

        let mut node = TmplNode {
            env_vars: new_node_envs(i, &conf, Some(typ)),
            image: conf.image_override(conf.node_impl(i)),
            ..TmplNode::default()
        };

        if !conf.disable_monitoring_ports {
            let offset = u32::try_from(i)
                .ok()
                .and_then(|i| i.checked_mul(10_000))
                .ok_or(ComposeError::PortOverflow { index: i })?;

            for mut port in CHARON_PORTS {
                port.external = port
                    .external
                    .checked_add(offset)
                    .ok_or(ComposeError::PortOverflow { index: i })?;
                node.ports.push(port);
            }
        }

        nodes.push(node);
    }

    let mut charon_cmd = CMD_RUN;

    if conf.p2p_fuzz {
        if let Some(first) = nodes.first_mut() {
            first
                .env_vars
                .push(Kv::new("p2p-fuzz", quoted_bool(conf.p2p_fuzz)));
        }

        charon_cmd = CMD_UNSAFE_RUN;
    }

    let data = TmplData {
        compose_dir: dir.to_string_lossy().into_owned(),
        charon_image_tag: conf.image_tag.clone(),
        charon_command: charon_cmd.to_string(),
        nodes,
        relay: true,
        monitoring: conf.monitoring,
        alerting: true,
        monitoring_ports: !conf.disable_monitoring_ports,
        vcs,
        ..TmplData::default()
    };

    info!("Created docker-compose.yml");
    info!("Run the cluster with: docker compose up");

    write_docker_compose(dir, &data)?;

    Ok(data)
}

/// Returns the validator client service for `typ` on node `node_idx`; the
/// mock client is charon's built-in one and needs no service.
fn get_vc(
    typ: VcType,
    node_idx: usize,
    num_vals: usize,
    insecure: bool,
    builder_api: bool,
) -> Result<TmplVc> {
    let mut resp = match typ {
        VcType::Mock => TmplVc::default(),
        VcType::Vouch | VcType::Lighthouse | VcType::Lodestar => TmplVc {
            label: typ.as_str().to_string(),
            build: typ.as_str().to_string(),
            ..TmplVc::default()
        },
        VcType::Teku => TmplVc {
            label: typ.as_str().to_string(),
            image: "consensys/teku:latest".to_string(),
            command: TEKU_COMMAND.to_string(),
            ..TmplVc::default()
        },
    };

    if typ == VcType::Teku {
        let keys: Vec<String> = (0..num_vals)
            .map(|i| {
                if insecure {
                    format!(
                        "/compose/node{node_idx}/validator_keys/keystore-insecure-{i}.json:/compose/node{node_idx}/validator_keys/keystore-insecure-{i}.txt"
                    )
                } else {
                    format!(
                        "/compose/node{node_idx}/validator_keys/keystore-{i}.json:/compose/node{node_idx}/validator_keys/keystore-{i}.txt"
                    )
                }
            })
            .collect();

        let node_idx =
            i64::try_from(node_idx).map_err(|_| ComposeError::PortOverflow { index: node_idx })?;

        let data = Value::object([
            ("TekuKeys", Value::str_list(keys)),
            ("NodeIdx", Value::Int(node_idx)),
            ("BuilderAPI", Value::Bool(builder_api)),
        ]);

        resp.command = Template::parse(&resp.command)
            .and_then(|tmpl| tmpl.execute(&data))
            .map_err(ComposeError::TekuTemplate)?;
    }

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test]
    fn teku_template_renders() {
        let vc = get_vc(VcType::Teku, 0, 1, false, true).expect("teku vc");
        assert_eq!(vc.label, "teku");
        assert_eq!(vc.image, "consensys/teku:latest");
        assert_eq!(
            vc.command,
            "|
      validator-client
      --network=auto
      --beacon-node-api-endpoint=\"http://node0:3600\"
      --validator-keys=\"/compose/node0/validator_keys/keystore-0.json:/compose/node0/validator_keys/keystore-0.txt\"
      --validators-proposer-default-fee-recipient=\"0x0000000000000000000000000000000000000000\"
      --validators-proposer-blinded-blocks-enabled=true"
        );
    }

    #[test]
    fn teku_template_insecure_keys_and_no_builder() {
        let vc = get_vc(VcType::Teku, 2, 2, true, false).expect("teku vc");
        assert!(vc.command.contains(
            "--validator-keys=\"/compose/node2/validator_keys/keystore-insecure-0.json:/compose/node2/validator_keys/keystore-insecure-0.txt\"\n      --validator-keys=\"/compose/node2/validator_keys/keystore-insecure-1.json:/compose/node2/validator_keys/keystore-insecure-1.txt\"\n      --validators-proposer-default"
        ), "{}", vc.command);
        assert!(
            vc.command
                .ends_with("--validators-proposer-blinded-blocks-enabled=false")
        );
    }

    #[test_case(VcType::Vouch, "vouch" ; "vouch")]
    #[test_case(VcType::Lighthouse, "lighthouse" ; "lighthouse")]
    #[test_case(VcType::Lodestar, "lodestar" ; "lodestar")]
    fn built_vcs(typ: VcType, name: &str) {
        let vc = get_vc(typ, 1, 1, false, false).expect("vc");
        assert_eq!(vc.label, name);
        assert_eq!(vc.build, name);
        assert!(vc.image.is_empty());
        assert!(vc.command.is_empty());
    }

    #[test]
    fn mock_vc_is_empty() {
        assert_eq!(
            get_vc(VcType::Mock, 0, 1, false, false).expect("vc"),
            TmplVc::default()
        );
    }

    #[test]
    fn run_rejects_non_locked_step() {
        let conf = Config::new_default();
        let dir = tempfile::tempdir().expect("tempdir");
        let err = run(dir.path(), conf).expect_err("must fail");
        assert_eq!(
            err.to_string(),
            "compose config not locked, so can't be run: step=new"
        );
    }

    #[test]
    fn run_requires_validator_clients() {
        let mut conf = Config::new_default();
        conf.step = Step::Locked;
        conf.vcs.clear();
        let dir = tempfile::tempdir().expect("tempdir");
        let err = run(dir.path(), conf).expect_err("must fail");
        assert_eq!(err.to_string(), "no validator clients configured");
    }

    #[test]
    fn run_p2p_fuzz_and_disabled_ports() {
        let mut conf = Config::new_default();
        conf.step = Step::Locked;
        conf.p2p_fuzz = true;
        conf.disable_monitoring_ports = true;

        let dir = tempfile::tempdir().expect("tempdir");
        let data = run(dir.path(), conf).expect("run");

        assert_eq!(data.charon_command, "[unsafe,run]");
        assert!(!data.monitoring_ports);
        assert!(data.nodes.iter().all(|n| n.ports.is_empty()));

        let fuzz = data.nodes[0].env_vars.last().expect("env");
        assert_eq!(
            (fuzz.key.as_str(), fuzz.value.as_str()),
            ("p2p-fuzz", "\"true\"")
        );
        assert!(data.nodes[1].env_vars.iter().all(|kv| kv.key != "p2p-fuzz"));
    }
}
