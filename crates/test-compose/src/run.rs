//! Cluster run step: node, validator client and monitoring services.

use std::path::Path;

use tracing::info;

use crate::{
    Result,
    config::{CHARON_PORTS, CMD_RUN, CMD_UNSAFE_RUN, Config, Step, VcType},
    error::ComposeError,
    lock::{NodeMode, new_node_envs, quoted_bool},
    template::{Kv, TmplData, TmplNode, TmplVc, write_docker_compose},
};

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

    for (i, &typ) in conf.vcs.iter().cycle().take(conf.num_nodes).enumerate() {
        vcs.push(get_vc(
            typ,
            i,
            conf.num_validators,
            conf.insecure_keys,
            conf.builder_api,
        ));

        let mut node = TmplNode {
            env_vars: new_node_envs(i, &conf, NodeMode::Run(typ)),
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
) -> TmplVc {
    match typ {
        VcType::Mock => TmplVc::default(),
        VcType::Vouch | VcType::Lighthouse | VcType::Lodestar => TmplVc {
            label: typ.to_string(),
            build: typ.to_string(),
            ..TmplVc::default()
        },
        VcType::Teku => TmplVc {
            label: typ.to_string(),
            image: "consensys/teku:26.8.0".to_string(),
            command: teku_command(node_idx, num_vals, insecure, builder_api),
            ..TmplVc::default()
        },
    }
}

/// The teku validator-client command as a YAML block scalar, one
/// `--validator-keys` pair per validator.
fn teku_command(node_idx: usize, num_vals: usize, insecure: bool, builder_api: bool) -> String {
    let mut cmd = format!(
        "|\n      validator-client\n      --network=auto\n      --beacon-node-api-endpoint=\"http://node{node_idx}:3600\"\n"
    );
    for i in 0..num_vals {
        let stem = if insecure {
            "keystore-insecure"
        } else {
            "keystore"
        };
        let dir = format!("/compose/node{node_idx}/validator_keys/{stem}-{i}");
        cmd.push_str(&format!(
            "      --validator-keys=\"{dir}.json:{dir}.txt\"\n"
        ));
    }
    cmd.push_str(
        "      --validators-proposer-default-fee-recipient=\"0x0000000000000000000000000000000000000000\"\n",
    );
    cmd.push_str(&format!(
        "      --validators-proposer-blinded-blocks-enabled={builder_api}"
    ));
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teku_command_renders() {
        let vc = get_vc(VcType::Teku, 0, 1, false, true);
        assert_eq!(vc.label, "teku");
        assert_eq!(vc.image, "consensys/teku:26.8.0");
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
    fn run_rejects_non_locked_step() {
        let conf = Config::new_default();
        let dir = tempfile::tempdir().expect("tempdir");
        let err = run(dir.path(), conf).expect_err("must fail");
        assert_eq!(
            err.to_string(),
            "compose config not locked, so can't be run: step=new"
        );
    }
}
