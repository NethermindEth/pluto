mod behaviour;
mod client;
mod error;
mod handler;
mod protocol;
mod server;

use libp2p::PeerId;
use pluto_core::version::SemVer;
use pluto_p2p::p2p_context::P2PContext;
use tokio::sync::mpsc;

pub use behaviour::{Behaviour, Event};
pub use client::{Client, ClientConfig, DEFAULT_PERIOD};
pub use error::{Error, Result};
pub use server::Server;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Command {
    Activate(PeerId),
}

/// Creates a sync behaviour plus server/client handles for the given peer set.
pub fn new(
    peers: Vec<PeerId>,
    p2p_context: P2PContext,
    secret: &k256::SecretKey,
    def_hash: Vec<u8>,
    version: SemVer,
) -> Result<(Behaviour, Server, Vec<Client>)> {
    let local_peer_id = p2p_context.local_peer_id().ok_or(Error::LocalPeerMissing)?;
    if !peers.contains(&local_peer_id) {
        return Err(Error::LocalPeerNotInPeerSet);
    }

    let hash_sig = protocol::sign_definition_hash(secret, &def_hash)?;
    let remote_peers = peers
        .into_iter()
        .filter(|peer_id| *peer_id != local_peer_id)
        .collect::<Vec<_>>();
    let server = Server::new(remote_peers.len(), def_hash, version.clone());
    let (command_tx, command_rx) = mpsc::unbounded_channel();
    let clients = remote_peers
        .into_iter()
        .map(|peer_id| {
            Client::new(
                peer_id,
                hash_sig.clone(),
                version.clone(),
                ClientConfig::default(),
                Some(command_tx.clone()),
            )
        })
        .collect::<Vec<_>>();
    let behaviour = Behaviour::new(server.clone(), clients.clone(), command_rx);
    Ok((behaviour, server, clients))
}

#[cfg(test)]
mod tests {
    use std::{net::TcpListener, time::Duration};

    use futures::StreamExt;
    use libp2p::PeerId;
    use pluto_core::version::SemVer;
    use pluto_p2p::{
        config::P2PConfig,
        p2p::{Node, NodeType},
        p2p_context::P2PContext,
        peer::peer_id_from_key,
    };
    use pluto_testutil::random::generate_insecure_k1_key;
    use tokio::{sync::oneshot, time::timeout};
    use tokio_util::sync::CancellationToken;

    use super::*;

    struct LocalNode {
        server: Server,
        clients: Vec<Client>,
        node: Node<Behaviour>,
        addr: libp2p::Multiaddr,
    }

    struct RunningNode {
        server: Server,
        clients: Vec<Client>,
        stop_tx: oneshot::Sender<()>,
        join: tokio::task::JoinHandle<anyhow::Result<()>>,
        client_joins: Vec<tokio::task::JoinHandle<Result<()>>>,
    }

    fn available_tcp_port() -> anyhow::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?.port())
    }

    async fn spawn_nodes(nodes: Vec<LocalNode>) -> anyhow::Result<Vec<RunningNode>> {
        let mut nodes = nodes;
        for node in &mut nodes {
            node.node.listen_on(node.addr.clone())?;
        }

        let dial_targets = (0..nodes.len())
            .map(|index| {
                nodes
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other > index)
                    .map(|(_, node)| node.addr.clone())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut running = Vec::with_capacity(nodes.len());
        for (local, targets) in nodes.into_iter().zip(dial_targets) {
            let mut node = local.node;
            let server = local.server.clone();
            server.start();
            let cancellation = CancellationToken::new();
            let client_joins = local
                .clients
                .iter()
                .map(|client| {
                    let cancellation = cancellation.child_token();
                    let client = client.clone();
                    tokio::spawn(async move { client.run(cancellation).await })
                })
                .collect::<Vec<_>>();
            let (stop_tx, mut stop_rx) = oneshot::channel();

            let join = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                for target in targets {
                    node.dial(target)?;
                }

                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        _event = node.select_next_some() => {}
                    }
                }

                Ok(())
            });

            running.push(RunningNode {
                server: local.server,
                clients: local.clients,
                stop_tx,
                join,
                client_joins,
            });
        }

        Ok(running)
    }

    async fn shutdown_nodes(nodes: Vec<RunningNode>) -> anyhow::Result<()> {
        for node in nodes {
            let _ = node.stop_tx.send(());
            node.join.await??;
            for join in node.client_joins {
                let _ = join.await;
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn update_step_rules_match_go() {
        let version = SemVer::parse("v0.1").expect("valid version");
        let server = Server::new(1, vec![0; 32], version);
        let peer = PeerId::random();

        let error = server
            .update_step(peer, 100)
            .await
            .expect_err("wrong initial step should fail");
        assert!(matches!(error, Error::AbnormalInitialStep));

        let peer = PeerId::random();
        server
            .update_step(peer, 1)
            .await
            .expect("first valid step should pass");
        server
            .update_step(peer, 1)
            .await
            .expect("same step should pass");
        server
            .update_step(peer, 2)
            .await
            .expect("next step should pass");

        let peer = PeerId::random();
        server
            .update_step(peer, 1)
            .await
            .expect("first step should pass");
        let error = server
            .update_step(peer, 0)
            .await
            .expect_err("behind should fail");
        assert!(matches!(error, Error::PeerStepBehind));

        let peer = PeerId::random();
        server
            .update_step(peer, 1)
            .await
            .expect("first step should pass");
        let error = server
            .update_step(peer, 4)
            .await
            .expect_err("ahead should fail");
        assert!(matches!(error, Error::PeerStepAhead));
    }

    #[test]
    fn new_requires_local_peer_in_peer_set() {
        let key = generate_insecure_k1_key(0);
        let local_peer_id = peer_id_from_key(key.public_key()).expect("peer id");
        let remote_peer = PeerId::random();
        let p2p_context = P2PContext::new([local_peer_id, remote_peer]);
        p2p_context.set_local_peer_id(local_peer_id);

        let result = new(
            vec![remote_peer],
            p2p_context,
            &key,
            vec![1, 2, 3],
            SemVer::parse("v1.7").expect("version"),
        );

        assert!(
            matches!(result, Err(Error::LocalPeerNotInPeerSet)),
            "local peer must be part of the sync peer set"
        );
    }

    #[tokio::test]
    async fn sync_round_trip_matches_go_shape() -> anyhow::Result<()> {
        let ports = (0..3)
            .map(|_| available_tcp_port())
            .collect::<anyhow::Result<Vec<_>>>()?;
        let keys = (0_u8..3).map(generate_insecure_k1_key).collect::<Vec<_>>();
        let peer_ids = keys
            .iter()
            .map(|key| peer_id_from_key(key.public_key()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let version = SemVer::parse("v1.7")?;
        let mut nodes = Vec::new();
        for (index, key) in keys.into_iter().enumerate() {
            let peer_id = peer_ids[index];
            let p2p_context = P2PContext::new(peer_ids.clone());
            p2p_context.set_local_peer_id(peer_id);
            let (behaviour, server, clients) = new(
                peer_ids.clone(),
                p2p_context.clone(),
                &key,
                vec![1, 2, 3],
                version.clone(),
            )?;
            let node = Node::new_server(
                P2PConfig::default(),
                key,
                NodeType::TCP,
                false,
                peer_ids.clone(),
                |builder, _keypair| builder.with_p2p_context(p2p_context).with_inner(behaviour),
            )?;
            let addr = format!("/ip4/127.0.0.1/tcp/{}", ports[index]).parse()?;
            nodes.push(LocalNode {
                server,
                clients,
                node,
                addr,
            });
        }

        let running = spawn_nodes(nodes).await?;
        let cancellation = CancellationToken::new();

        for node in &running {
            timeout(
                Duration::from_secs(10),
                node.server.await_all_connected(cancellation.child_token()),
            )
            .await??;
        }

        for step in 0_i64..5 {
            for node in &running {
                timeout(
                    Duration::from_secs(10),
                    node.server
                        .await_all_at_step(step, cancellation.child_token()),
                )
                .await??;

                let future = node
                    .server
                    .await_all_at_step(step + 1, cancellation.child_token());
                let error = timeout(Duration::from_millis(10), future).await;
                assert!(error.is_err(), "next step should not complete immediately");
            }

            for node in &running {
                for client in &node.clients {
                    client.set_step(step + 1);
                }
            }
        }

        for node in &running {
            assert!(node.clients.iter().all(Client::is_connected));
        }

        for node in &running {
            for client in &node.clients {
                client.shutdown(cancellation.child_token()).await?;
            }
        }

        for node in &running {
            timeout(
                Duration::from_secs(10),
                node.server.await_all_shutdown(cancellation.child_token()),
            )
            .await??;
        }

        shutdown_nodes(running).await?;
        Ok(())
    }
}
