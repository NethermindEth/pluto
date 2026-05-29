use std::{
    collections::BTreeMap,
    error::Error as StdError,
    sync::{Arc, Mutex},
    time::Duration,
};

use pluto_core::{
    corepb::v1::core as pbcore,
    types::{Duty, DutyType, SlotNumber},
};
use prost::bytes::Bytes;
use test_case::test_case;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{
    Peer,
    component::{self, Config, Consensus},
};

#[test_case(2, 3 ; "two_of_three")]
#[test_case(3, 4 ; "three_of_four")]
#[test_case(4, 4 ; "four_of_four")]
#[test_case(4, 6 ; "four_of_six")]
#[tokio::test]
async fn qbft_consensus(threshold: usize, cluster_nodes: usize) {
    assert!(threshold <= cluster_nodes);
    let (sniffed_tx, mut sniffed_rx) = mpsc::unbounded_channel();
    let active_nodes = in_memory_network(threshold, sniffed_tx);
    let (decided_tx, mut decided_rx) = mpsc::unbounded_channel();
    let duty = Duty::new(SlotNumber::new(1), DutyType::Attester);
    let ct = CancellationToken::new();
    let start_ct = CancellationToken::new();
    let mut expired_txs = Vec::with_capacity(active_nodes.len());
    let mut start_tasks = Vec::with_capacity(active_nodes.len());

    for (node_idx, node) in active_nodes.iter().enumerate() {
        let decided_tx = decided_tx.clone();
        node.subscribe(move |duty, value| {
            let _ = decided_tx.send((node_idx, duty, value));
            Ok(())
        });

        let (expired_tx, expired_rx) = mpsc::channel(1);
        expired_txs.push(expired_tx);
        start_tasks.push(Arc::clone(node).start(start_ct.clone(), expired_rx));
    }
    drop(decided_tx);

    let mut tasks = Vec::with_capacity(active_nodes.len());
    for (node_idx, node) in active_nodes.iter().enumerate() {
        let node = Arc::clone(node);
        let duty = duty.clone();
        let value = unsigned_value(node_idx);
        let ct = ct.clone();
        tasks.push(tokio::spawn(
            async move { node.propose(&ct, duty, value).await },
        ));
    }

    let mut decided = Vec::with_capacity(active_nodes.len());
    for _ in 0..active_nodes.len() {
        decided.push(recv_one(&mut decided_rx).await);
    }

    for task in tasks {
        task.await.unwrap().unwrap();
    }

    decided.sort_by_key(|(node_idx, ..)| *node_idx);
    assert_eq!(decided.len(), threshold);
    let (_, _, expected_value) = decided.first().expect("at least one decided value").clone();
    for (node_idx, decided_duty, decided_value) in decided {
        assert_eq!(decided_duty, duty, "node {node_idx} decided wrong duty");
        assert_eq!(
            decided_value, expected_value,
            "node {node_idx} decided different value"
        );
    }

    ct.cancel();
    start_ct.cancel();
    drop(expired_txs);
    for task in start_tasks {
        task.await.unwrap();
    }

    let mut sniffed = Vec::with_capacity(threshold);
    for _ in 0..threshold {
        sniffed.push(recv_one(&mut sniffed_rx).await);
    }
    sniffed.sort_by_key(|(node_idx, _)| *node_idx);
    for (node_idx, msg_count) in sniffed {
        assert_ne!(msg_count, 0, "node {node_idx} sniffer was empty");
    }
}

async fn recv_one<T>(rx: &mut mpsc::UnboundedReceiver<T>) -> T {
    tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("receiver timed out")
        .expect("receiver closed")
}

fn unsigned_value(seed: usize) -> pbcore::UnsignedDataSet {
    let mut set = BTreeMap::new();
    set.insert(
        format!("validator-{seed}"),
        Bytes::from(format!("unsigned-{seed}")),
    );
    pbcore::UnsignedDataSet { set }
}

fn in_memory_network(
    count: usize,
    sniffed_tx: mpsc::UnboundedSender<(usize, usize)>,
) -> Vec<Arc<Consensus>> {
    let peers = (0..count)
        .map(|index| Peer {
            index: i64::try_from(index).expect("test peer index fits i64"),
            name: format!("node-{index}"),
            public_key: component::tests::secret_key(
                u8::try_from(index.checked_add(1).expect("test peer index increments"))
                    .expect("test peer index fits u8"),
            )
            .public_key(),
        })
        .collect::<Vec<_>>();
    let nodes = Arc::new(Mutex::new(Vec::<Arc<Consensus>>::new()));

    for index in 0..count {
        let network = Arc::clone(&nodes);
        let broadcaster: component::Broadcaster = Arc::new(move |ct, msg| {
            let network = Arc::clone(&network);
            Box::pin(async move {
                let peer_idx = msg.msg.as_ref().map_or(-1, |msg| msg.peer_idx);
                let peers = network.lock().unwrap().clone();
                for (index, consensus) in peers.into_iter().enumerate() {
                    if i64::try_from(index).expect("test peer index fits i64") == peer_idx {
                        continue;
                    }
                    if let Err(err) = consensus.handle(&ct, Some(msg.clone())).await {
                        return Err(Box::new(err) as Box<dyn StdError + Send + Sync>);
                    }
                }
                Ok(())
            })
        });
        let consensus = Arc::new(
            Consensus::new(Config {
                peers: peers.clone(),
                local_peer_idx: i64::try_from(index).expect("test peer index fits i64"),
                privkey: component::tests::secret_key(
                    u8::try_from(index.checked_add(1).expect("test peer index increments"))
                        .expect("test peer index fits u8"),
                ),
                broadcaster,
                compare_attestations: false,
                sniffer: {
                    let sniffed_tx = sniffed_tx.clone();
                    Arc::new(move |instance| {
                        let _ = sniffed_tx.send((index, instance.msgs.len()));
                    })
                },
                ..component::tests::config_base(false)
            })
            .unwrap(),
        );
        nodes.lock().unwrap().push(consensus);
    }

    nodes.lock().unwrap().clone()
}
