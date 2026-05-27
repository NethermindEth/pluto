use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    bcast,
    dkg::{Config, DkgError},
    exchanger::{SIG_DEPOSIT_DATA, SigType},
    frostp2p, sync,
};
use libp2p::{Multiaddr, multiaddr::Protocol, relay, swarm::NetworkBehaviour};
use pluto_core::{
    types::{Duty, DutyType},
    version,
};
use pluto_p2p::{
    bootnode, gater,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::{Peer, peer_id_from_key, verify_p2p_key},
    relay::RelayManager,
};
use pluto_parsigex as parsigex;
use pluto_peerinfo::{self as peerinfo, LocalPeerInfo};
use tokio_util::sync::CancellationToken;

#[derive(NetworkBehaviour)]
pub(crate) struct DkgBehaviour {
    pub(crate) relay: relay::client::Behaviour,
    pub(crate) relay_manager: RelayManager,
    pub(crate) bcast: bcast::Behaviour,
    pub(crate) sync: sync::Behaviour,
    pub(crate) parsigex: parsigex::Behaviour,
    pub(crate) peerinfo: peerinfo::Behaviour,
    pub(crate) frost_p2p: frostp2p::FrostP2PBehaviour,
}

type Result<T> = std::result::Result<T, DkgError>;

pub(crate) struct Handlers {
    pub(crate) bcast: bcast::Component,
    pub(crate) sync: Vec<sync::Client>,
    pub(crate) sync_server: sync::Server,
    pub(crate) parsigex: parsigex::Handle,
    pub(crate) frost_p2p: frostp2p::FrostP2PHandle,
}

pub(crate) async fn setup_p2p(
    key: k256::SecretKey,
    conf: &Config,
    peers: &[Peer],
    def_hash: Vec<u8>,
    sig_types: Arc<HashSet<SigType>>,
    num_validators: u32,
    ct: CancellationToken,
) -> Result<(Node<DkgBehaviour>, Handlers)> {
    let peer_ids = peers.iter().map(|peer| peer.id).collect::<Vec<_>>();
    let local_peer_id = peer_id_from_key(key.public_key())?;

    verify_p2p_key(peers, &key)?;

    let relay_addrs = relay_addrs_for_resolution(&conf.p2p.relays);
    let relays = bootnode::new_relays(ct, &relay_addrs, &hex::encode(&def_hash)).await?;

    let conn_gater = gater::ConnGater::new_conn_gater(peer_ids.clone(), relays.clone());

    let p2p_context = P2PContext::new(peer_ids.clone());
    p2p_context.set_local_peer_id(local_peer_id);

    let relay_manager = RelayManager::new(relays, p2p_context.clone());

    let (bcast_comp, bcast_comp_handle) =
        bcast::Behaviour::new(peer_ids.clone(), p2p_context.clone(), key.clone());
    let (sync_comp, sync_server, sync_clients) = sync::new(
        peer_ids.clone(),
        p2p_context.clone(),
        &key,
        def_hash.clone(),
        version::VERSION.to_minor(),
    )?;

    let parsigex_config = parsigex::Config::new(
        local_peer_id,
        p2p_context.clone(),
        Arc::new(|_duty, _pk, _sig| Box::pin(async { Ok(()) })),
        Arc::new(move |duty: &Duty| {
            if duty.duty_type != DutyType::Signature {
                return false;
            }

            if sig_types.contains(&SIG_DEPOSIT_DATA) && duty.slot.inner() >= SIG_DEPOSIT_DATA {
                return true;
            }

            sig_types.contains(&duty.slot.inner())
        }),
    )
    .with_timeout(conf.timeout);

    let (parsigex_comp, parsigex_handle) = parsigex::Behaviour::new(parsigex_config);

    let (git_hash, _) = version::git_commit();
    let peerinfo_config = peerinfo::Config::new(LocalPeerInfo::new(
        version::VERSION.to_string(),
        def_hash.clone(),
        git_hash,
        false,
        "",
    ))
    .with_peers(peer_ids.clone());
    let peerinfo_comp = peerinfo::Behaviour::new(local_peer_id, peerinfo_config);

    let mut share_idx_by_peer = HashMap::new();
    let mut local_share_idx = None;
    for peer in peers {
        let share_idx = u32::try_from(peer.share_idx())?;
        share_idx_by_peer.insert(peer.id, share_idx);
        if peer.id == local_peer_id {
            local_share_idx = Some(share_idx);
        }
    }
    let local_share_idx = local_share_idx.ok_or(DkgError::LocalPeerNotInDefinition {
        peer_id: local_peer_id,
    })?;

    let (frost_p2p_comp, frost_p2p_handle) = frostp2p::FrostP2PBehaviour::new(
        p2p_context.clone(),
        peer_ids.clone(),
        share_idx_by_peer,
        local_share_idx,
        num_validators as usize,
    );

    let node = Node::new(
        conf.p2p.clone(),
        key,
        NodeType::TCP,
        false,
        p2p_context,
        |builder, _, relay_client| {
            builder.with_gater(conn_gater).with_inner(DkgBehaviour {
                relay: relay_client,
                relay_manager,
                bcast: bcast_comp,
                sync: sync_comp,
                parsigex: parsigex_comp,
                peerinfo: peerinfo_comp,
                frost_p2p: frost_p2p_comp,
            })
        },
    )?;

    let handlers = Handlers {
        bcast: bcast_comp_handle,
        sync: sync_clients,
        sync_server,
        parsigex: parsigex_handle,
        frost_p2p: frost_p2p_handle,
    };

    Ok((node, handlers))
}

fn relay_addrs_for_resolution(relays: &[Multiaddr]) -> Vec<String> {
    relays.iter().map(relay_addr_for_resolution).collect()
}

fn relay_addr_for_resolution(relay: &Multiaddr) -> String {
    let mut scheme = None;
    let mut host = None;
    let mut port = None;

    for protocol in relay.iter() {
        match protocol {
            Protocol::Http => scheme = Some("http"),
            Protocol::Https => scheme = Some("https"),
            Protocol::Dns(name)
            | Protocol::Dns4(name)
            | Protocol::Dns6(name)
            | Protocol::Dnsaddr(name)
                if host.is_none() =>
            {
                host = Some(name.to_string());
            }
            Protocol::Ip4(ip) if host.is_none() => {
                host = Some(ip.to_string());
            }
            Protocol::Ip6(ip) if host.is_none() => {
                host = Some(format!("[{ip}]"));
            }
            Protocol::Tcp(tcp_port) => port = Some(tcp_port),
            _ => {}
        }
    }

    if let (Some(scheme), Some(host)) = (scheme, host) {
        let default_port = match scheme {
            "https" => 443,
            _ => 80,
        };

        return match port {
            Some(port) if port != default_port => format!("{scheme}://{host}:{port}"),
            _ => format!("{scheme}://{host}"),
        };
    }

    relay.to_string()
}
