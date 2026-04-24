#![allow(missing_docs)]
//! Partial-signature exchange example.
//!
//! Each node periodically broadcasts a synthetic [`ParSignedDataSet`] to all
//! cluster peers over the relay-routed libp2p network and logs every dataset it
//! receives from others.
//!
//! # Running a multi-node setup
//!
//! ## 1. Create a cluster
//!
//! Use the built-in Pluto CLI to generate per-node data directories, each
//! containing a `charon-enr-private-key` and a shared `cluster-lock.json`:
//!
//! ```bash
//! cargo run -p pluto-cli -- create cluster --name parsigex-test --nodes 3 \
//!   --threshold 2 --num-validators 1 --network mainnet --insecure-keys \
//!   --fee-recipient-addresses 0x0000000000000000000000000000000000000000 \
//!   --withdrawal-addresses 0x0000000000000000000000000000000000000000 \
//!   --cluster-dir ./cluster
//! ```
//!
//! This writes `./cluster/node{0,1,2}/` — each directory is ready to use as
//! `--data-dir`.
//!
//! ## 2. Run each node
//!
//! Obol operates public relay servers. Pass one or more via `--relays` and
//! point `--data-dir` at the corresponding node directory from Step 1:
//!
//! ```bash
//! # Terminal 1
//! cargo run -p pluto-parsigex --example parsigex -- \
//!   --relays https://0.relay.obol.tech,https://1.relay.obol.tech \
//!   --data-dir ./cluster/node0 --share-idx 1
//!
//! # Terminal 2
//! cargo run -p pluto-parsigex --example parsigex -- \
//!   --relays https://0.relay.obol.tech,https://1.relay.obol.tech \
//!   --data-dir ./cluster/node1 --share-idx 2
//!
//! # Terminal 3
//! cargo run -p pluto-parsigex --example parsigex -- \
//!   --relays https://0.relay.obol.tech,https://1.relay.obol.tech \
//!   --data-dir ./cluster/node2 --share-idx 3
//! ```
//!
//! Nodes discover each other through the relay and exchange partial signatures
//! every `--broadcast-every` seconds (default: 10). Look for log lines:
//!
//! ```text
//! INFO received partial signature set peer=... duty=... entries=...
//! INFO broadcasted sample partial signature set request_id=... duty=...
//! ```
//!
//! `--relays` also accepts raw libp2p multiaddrs
//! (`/ip4/IP/tcp/PORT/p2p/PEER_ID`) and multiple comma-separated values.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use futures::StreamExt;
use libp2p::{
    identify, ping,
    relay::{self},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use pluto_cluster::lock::Lock;
use pluto_core::{
    signeddata::SignedRandao,
    types::{Duty, DutyType, ParSignedDataSet, PubKey, SlotNumber},
};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    bootnode,
    config::P2PConfig,
    gater, k1,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::peer_id_from_key,
    relay::{MutableRelayReservation, RelayRouter},
};
use pluto_parsigex::{self as parsigex, DutyGater, Event, Handle, Verifier};
use pluto_tracing::TracingConfig;
use tokio::fs;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "CombinedBehaviourEvent")]
struct CombinedBehaviour {
    relay: relay::client::Behaviour,
    relay_reservation: MutableRelayReservation,
    relay_router: RelayRouter,
    parsigex: parsigex::Behaviour,
}

#[derive(Debug)]
enum CombinedBehaviourEvent {
    ParSigEx(Event),
    Relay(relay::client::Event),
}

impl From<Event> for CombinedBehaviourEvent {
    fn from(event: Event) -> Self {
        Self::ParSigEx(event)
    }
}

impl From<relay::client::Event> for CombinedBehaviourEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::Relay(event)
    }
}

impl From<std::convert::Infallible> for CombinedBehaviourEvent {
    fn from(value: std::convert::Infallible) -> Self {
        match value {}
    }
}

#[derive(Debug, Parser)]
#[command(name = "parsigex-example")]
#[command(about = "Demonstrates partial signature exchange over the bootnode/relay P2P path")]
struct Args {
    /// Relay URLs or multiaddrs.
    #[arg(long, value_delimiter = ',')]
    relays: Vec<String>,

    /// Directory holding the p2p private key and cluster lock.
    #[arg(long)]
    data_dir: PathBuf,

    /// TCP listen addresses.
    #[arg(long, value_delimiter = ',', default_value = "0.0.0.0:0")]
    tcp_addrs: Vec<String>,

    /// UDP listen addresses used for QUIC.
    #[arg(long, value_delimiter = ',', default_value = "0.0.0.0:0")]
    udp_addrs: Vec<String>,

    /// Whether to filter private addresses from advertisements.
    #[arg(long, default_value_t = false)]
    filter_private_addrs: bool,

    /// External IP address to advertise.
    #[arg(long)]
    external_ip: Option<String>,

    /// External hostname to advertise.
    #[arg(long)]
    external_host: Option<String>,

    /// Whether to disable socket reuse-port.
    #[arg(long, default_value_t = false)]
    disable_reuse_port: bool,

    /// Emit a sample partial signature every N seconds.
    #[arg(long, default_value_t = 10)]
    broadcast_every: u64,

    /// Share index to use in the sample partial signature.
    #[arg(long, default_value_t = 1)]
    share_idx: u64,

    /// Log level.
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn make_sample_set(slot: u64, share_idx: u64) -> ParSignedDataSet {
    let share_byte = u8::try_from(share_idx % 255).unwrap_or(1);
    let pub_key = PubKey::new([share_byte; 48]);

    let mut set = ParSignedDataSet::new();
    set.insert(
        pub_key,
        SignedRandao::new_partial(slot / 32, [share_byte; 96], share_idx),
    );
    set
}

fn log_received(duty: &Duty, set: &ParSignedDataSet, peer: &libp2p::PeerId) {
    let entries = set
        .inner()
        .iter()
        .map(|(pub_key, data)| format!("{pub_key}:share_idx={}", data.share_idx))
        .collect::<Vec<_>>()
        .join(", ");

    info!(peer = %peer, duty = %duty, entries = %entries, "received partial signature set");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    pluto_tracing::init(
        &TracingConfig::builder()
            .with_default_console()
            .override_env_filter(&args.log_level)
            .build(),
    )?;

    let key = k1::load_priv_key(&args.data_dir).with_context(|| {
        format!(
            "failed to load private key from {}",
            args.data_dir.display()
        )
    })?;
    let local_peer_id = peer_id_from_key(key.public_key())
        .context("failed to derive local peer ID from private key")?;

    let lock_path = args.data_dir.join("cluster-lock.json");
    let lock_str = fs::read_to_string(&lock_path)
        .await
        .with_context(|| format!("failed to read {}", lock_path.display()))?;
    let lock: Lock = serde_json::from_str(&lock_str)
        .with_context(|| format!("failed to parse {}", lock_path.display()))?;

    let cancel = CancellationToken::new();
    let lock_hash_hex = hex::encode(&lock.lock_hash);
    let relays = bootnode::new_relays(cancel.child_token(), &args.relays, &lock_hash_hex)
        .await
        .context("failed to resolve relays")?;

    let known_peers = lock
        .peer_ids()
        .context("failed to derive peer IDs from lock")?;
    if !known_peers.contains(&local_peer_id) {
        return Err(anyhow!(
            "local peer ID {local_peer_id} not found in cluster lock"
        ));
    }
    let conn_gater = gater::ConnGater::new(
        gater::Config::closed()
            .with_relays(relays.clone())
            .with_peer_ids(known_peers.clone()),
    );

    let verifier: Verifier =
        std::sync::Arc::new(|_duty, _pubkey, _data| Box::pin(async { Ok(()) }));
    let duty_gater: DutyGater = std::sync::Arc::new(|duty| duty.duty_type != DutyType::Unknown);
    let handle_slot = std::sync::Arc::new(tokio::sync::Mutex::new(1_u64));

    let p2p_config = P2PConfig {
        relays: vec![],
        external_ip: args.external_ip.clone(),
        external_host: args.external_host.clone(),
        tcp_addrs: args.tcp_addrs.clone(),
        udp_addrs: args.udp_addrs.clone(),
        disable_reuse_port: args.disable_reuse_port,
    };

    let relay_peer_ids: HashSet<_> = relays
        .iter()
        .filter_map(|relay| relay.peer().ok().flatten().map(|peer| peer.id))
        .collect();

    let mut parsigex_handle: Option<Handle> = None;
    let mut node: Node<CombinedBehaviour> = Node::new(
        p2p_config,
        key,
        NodeType::QUIC,
        args.filter_private_addrs,
        P2PContext::new(known_peers.clone()),
        |builder, keypair, relay_client| {
            let p2p_context = builder.p2p_context();
            let local_peer_id = keypair.public().to_peer_id();
            let config = parsigex::Config::new(
                local_peer_id,
                p2p_context.clone(),
                verifier.clone(),
                duty_gater.clone(),
            )
            .with_timeout(Duration::from_secs(10));
            let (parsigex, handle) = parsigex::Behaviour::new(config);
            parsigex_handle = Some(handle);

            builder
                .with_gater(conn_gater)
                .with_inner(CombinedBehaviour {
                    parsigex,
                    relay: relay_client,
                    relay_reservation: MutableRelayReservation::new(relays.clone()),
                    relay_router: RelayRouter::new(relays.clone(), p2p_context, local_peer_id),
                })
        },
    )?;

    let parsigex_handle =
        parsigex_handle.ok_or_else(|| anyhow!("parsigex handle should be created"))?;

    info!(
        peer_id = %node.local_peer_id(),
        data_dir = %args.data_dir.display(),
        known_peers = ?known_peers,
        relays = ?args.relays,
        "parsigex example started"
    );

    let mut ticker = tokio::time::interval(Duration::from_secs(args.broadcast_every));
    let mut pending_broadcasts: HashMap<u64, (Duty, u64)> = HashMap::new();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl+c received, shutting down");
                break;
            }
            _ = ticker.tick() => {
                info!("broadcasting sample partial signature set");
                let mut slot = handle_slot.lock().await;
                let duty = Duty::new(SlotNumber::new(*slot), DutyType::Randao);
                let data_set = make_sample_set(*slot, args.share_idx);

                match parsigex_handle.broadcast(duty.clone(), data_set.clone()).await {
                    Ok(request_id) => {
                        pending_broadcasts.insert(request_id, (duty.clone(), args.share_idx));
                        info!(
                            request_id,
                            duty = %duty,
                            share_idx = args.share_idx,
                            "queued sample partial signature set for broadcast"
                        );
                        *slot = slot.saturating_add(1);
                    }
                    Err(error) => {
                        warn!(%error, "broadcast failed");
                    }
                }
            }
            event = node.select_next_some() => {
                let peer_type = |peer_id: &libp2p::PeerId| {
                    if relay_peer_ids.contains(peer_id) {
                        "RELAY"
                    } else if known_peers.contains(peer_id) {
                        "PEER"
                    } else {
                        "UNKNOWN"
                    }
                };

                match event {
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        CombinedBehaviourEvent::Relay(relay::client::Event::ReservationReqAccepted {
                            relay_peer_id,
                            renewal,
                            limit,
                        }),
                    )) => {
                        info!(
                            relay_peer_id = %relay_peer_id,
                            peer_type = peer_type(&relay_peer_id),
                            renewal,
                            limit = ?limit,
                            "relay reservation accepted"
                        );
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        CombinedBehaviourEvent::Relay(relay::client::Event::OutboundCircuitEstablished {
                            relay_peer_id,
                            limit,
                        }),
                    )) => {
                        info!(
                            relay_peer_id = %relay_peer_id,
                            peer_type = peer_type(&relay_peer_id),
                            limit = ?limit,
                            "outbound relay circuit established"
                        );
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        CombinedBehaviourEvent::Relay(relay::client::Event::InboundCircuitEstablished {
                            src_peer_id,
                            limit,
                        }),
                    )) => {
                        info!(
                            src_peer_id = %src_peer_id,
                            peer_type = peer_type(&src_peer_id),
                            limit = ?limit,
                            "inbound relay circuit established"
                        );
                    }
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        endpoint,
                        num_established,
                        ..
                    } => {
                        let address = match &endpoint {
                            libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
                            libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                                send_back_addr
                            }
                        };
                        info!(
                            peer_id = %peer_id,
                            peer_type = peer_type(&peer_id),
                            address = %address,
                            num_established,
                            "connection established"
                        );
                    }
                    SwarmEvent::ConnectionClosed {
                        peer_id,
                        endpoint,
                        num_established,
                        cause,
                        ..
                    } => {
                        let address = match &endpoint {
                            libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
                            libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                                send_back_addr
                            }
                        };
                        info!(
                            peer_id = %peer_id,
                            peer_type = peer_type(&peer_id),
                            address = %address,
                            num_established,
                            cause = ?cause,
                            "connection closed"
                        );
                    }
                    SwarmEvent::OutgoingConnectionError {
                        peer_id,
                        error,
                        connection_id,
                    } => {
                        warn!(
                            peer_id = ?peer_id,
                            connection_id = ?connection_id,
                            error = %error,
                            "outgoing connection failed"
                        );
                    }
                    SwarmEvent::IncomingConnectionError {
                        connection_id,
                        local_addr,
                        send_back_addr,
                        error,
                        ..
                    } => {
                        warn!(
                            connection_id = ?connection_id,
                            local_addr = %local_addr,
                            send_back_addr = %send_back_addr,
                            error = %error,
                            "incoming connection failed"
                        );
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. },
                    )) => {
                        info!(
                            peer_id = %peer_id,
                            peer_type = peer_type(&peer_id),
                            agent_version = %info.agent_version,
                            protocol_version = %info.protocol_version,
                            listen_addrs = ?info.listen_addrs,
                            "identify received"
                        );
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(ping::Event {
                        peer,
                        result,
                        ..
                    })) => match result {
                        Ok(rtt) => {
                            info!(peer_id = %peer, peer_type = peer_type(&peer), rtt = ?rtt, "ping succeeded");
                        }
                        Err(error) => {
                            warn!(peer_id = %peer, peer_type = peer_type(&peer), error = %error, "ping failed");
                        }
                    },
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        CombinedBehaviourEvent::ParSigEx(Event::Received {
                            peer,
                            duty,
                            data_set,
                            ..
                        }),
                    )) => {
                        log_received(&duty, &data_set, &peer);
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        CombinedBehaviourEvent::ParSigEx(Event::Error { peer, error, .. }),
                    )) => {
                        warn!(peer = %peer, error = %error, "parsigex protocol error");
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        CombinedBehaviourEvent::ParSigEx(Event::BroadcastError {
                            request_id,
                            peer,
                            error,
                        }),
                    )) => {
                        match pending_broadcasts.get(&request_id) {
                            Some((duty, share_idx)) => {
                                warn!(
                                    request_id,
                                    duty = %duty,
                                    share_idx,
                                    peer = ?peer,
                                    error = %error,
                                    "sample partial signature broadcast failed"
                                );
                            }
                            None => {
                                warn!(
                                    request_id,
                                    peer = ?peer,
                                    error = %error,
                                    "partial signature broadcast failed"
                                );
                            }
                        }
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        CombinedBehaviourEvent::ParSigEx(Event::BroadcastComplete {
                            request_id,
                        }),
                    )) => {
                        if let Some((duty, share_idx)) = pending_broadcasts.remove(&request_id) {
                            info!(
                                request_id,
                                duty = %duty,
                                share_idx,
                                "broadcasted sample partial signature set"
                            );
                        } else {
                            info!(request_id, "partial signature broadcast completed");
                        }
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        CombinedBehaviourEvent::ParSigEx(Event::BroadcastFailed {
                            request_id,
                        }),
                    )) => {
                        if let Some((duty, share_idx)) = pending_broadcasts.remove(&request_id) {
                            warn!(
                                request_id,
                                duty = %duty,
                                share_idx,
                                "sample partial signature broadcast finished with failures"
                            );
                        } else {
                            warn!(request_id, "partial signature broadcast finished with failures");
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
