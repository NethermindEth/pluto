//! Bootnode and relay resolution functionality.

use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use libp2p::Multiaddr;
use pluto_eth2util::enr::Record;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::peer::{
    AddrInfo, MutablePeer, MutablePeerError, Peer, PeerError, addr_infos_from_p2p_addrs,
    peer_id_from_key,
};

/// Backoff configuration constants matching Go's expbackoff.FastConfig.
const FAST_BASE_DELAY: Duration = Duration::from_millis(100);
const FAST_MAX_DELAY: Duration = Duration::from_secs(5);
const FAST_MULTIPLIER: f32 = 1.6;

/// Polling interval for relay address updates.
const RELAY_POLL_INTERVAL: Duration = Duration::from_secs(120); // 2 minutes

/// Timeout for resolving at least one bootnode ENR.
const BOOTNODE_RESOLVE_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval for checking bootnode resolution status.
const BOOTNODE_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Bootnode error.
#[derive(Debug, thiserror::Error)]
pub enum BootnodeError {
    /// Invalid relay multiaddr.
    #[error("invalid relay multiaddr: {0}")]
    InvalidRelayMultiaddr(String),

    /// Failed to get peer from multiaddr.
    #[error("peer from multiaddr: {0}")]
    PeerFromMultiaddr(String),

    /// Failed to parse relay URL.
    #[error("parse relay url")]
    ParseRelayUrl(#[from] url::ParseError),

    /// Invalid relay URL (not http/https).
    #[error("invalid relay url")]
    InvalidRelayUrl,

    /// HTTP request error.
    #[error("new request: {0}")]
    NewRequest(#[from] reqwest::Error),

    /// Timeout resolving bootnode ENR.
    #[error("timeout resolving bootnode ENR")]
    TimeoutResolvingBootnodeEnr,

    /// Timeout querying relay addresses.
    #[error("timeout querying relay addresses")]
    TimeoutQueryingRelayAddresses,

    /// Failed to parse ENR.
    #[error("parse ENR: {0}")]
    ParseEnr(#[from] pluto_eth2util::enr::RecordError),

    /// ENR does not have an IP.
    #[error("enr does not have an IP")]
    EnrNoIp,

    /// Failed to get peer ID from ENR key.
    #[error("get peer ID from ENR key: {0}")]
    GetPeerIdFromEnrKey(#[from] PeerError),

    /// Failed to create QUIC-v1 multiaddr.
    #[error("create quic-v1 multiaddr: {0}")]
    CreateQuicMultiaddr(libp2p::multiaddr::Error),

    /// Failed to create TCP multiaddr.
    #[error("create tcp multiaddr: {0}")]
    CreateTcpMultiaddr(libp2p::multiaddr::Error),

    /// ENR does not have TCP nor UDP port.
    #[error("enr does not have TCP nor UDP port")]
    EnrNoPort,

    /// Mutable peer error.
    #[error("mutable peer error: {0}")]
    MutablePeerError(#[from] MutablePeerError),
}

/// Result type for bootnode operations.
pub type Result<T> = std::result::Result<T, BootnodeError>;

/// Returns the libp2p relays from the provided addresses.
///
/// For HTTP(S) URLs, spawns a background task to continuously resolve relay
/// addresses. For multiaddrs, parses directly and creates a MutablePeer.
/// Waits up to 1 minute for at least one ENR to resolve.
pub async fn new_relays(
    cancel: CancellationToken,
    relays: &[String],
    lock_hash_hex: &str,
) -> Result<Vec<MutablePeer>> {
    let mut resp = Vec::new();

    for relay_addr in relays {
        if relay_addr.starts_with("http") {
            if !relay_addr.starts_with("https") {
                warn!(addr = %relay_addr, "Relay URL does not use https protocol");
            }

            let mutable = MutablePeer::default();
            let url = relay_addr.clone();
            let hash = lock_hash_hex.to_string();
            let mutable_clone = mutable.clone();
            let cancel_clone = cancel.child_token();

            tokio::spawn(async move {
                resolve_relay(cancel_clone, url, hash, mutable_clone).await;
            });

            resp.push(mutable);
            continue;
        }

        let addr: Multiaddr = relay_addr
            .parse()
            .map_err(|_| BootnodeError::InvalidRelayMultiaddr(relay_addr.clone()))?;

        let info = addr_info_from_p2p_addr(&addr)
            .map_err(|_| BootnodeError::PeerFromMultiaddr(relay_addr.clone()))?;

        resp.push(MutablePeer::new(Peer::new_relay_peer(&info)));
    }

    if resp.is_empty() {
        return Ok(resp);
    }

    let resp = tokio::time::timeout(BOOTNODE_RESOLVE_TIMEOUT, async {
        loop {
            if cancel.is_cancelled() {
                return Err(BootnodeError::TimeoutResolvingBootnodeEnr);
            }

            let mut resolved = false;
            for node in &resp {
                if let Ok(Some(_)) = node.peer() {
                    resolved = true;
                    break;
                }
            }

            if resolved {
                return Ok(resp);
            }

            tokio::time::sleep(BOOTNODE_CHECK_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| BootnodeError::TimeoutResolvingBootnodeEnr)??;

    Ok(resp)
}

/// Continuously resolves relay multiaddrs from an HTTP URL and updates the
/// MutablePeer.
///
/// Polls the URL every 2 minutes and calls the callback when peer info changes.
async fn resolve_relay(
    cancel: CancellationToken,
    raw_url: String,
    lock_hash_hex: String,
    mutable: MutablePeer,
) {
    let mut prev_addrs = String::new();
    let client = reqwest::Client::new();

    loop {
        if cancel.is_cancelled() {
            return;
        }

        let addrs = match query_relay_addrs(cancel.clone(), &client, &raw_url, &lock_hash_hex).await
        {
            Ok(addrs) => addrs,
            Err(e) => {
                tracing::error!(err = %e, url = %raw_url, "Failed resolving relay addresses from URL");
                return;
            }
        };

        let mut sorted_addrs = addrs.clone();
        sorted_addrs.sort_by_key(|a| a.to_string());

        let new_addrs = format!("{sorted_addrs:?}");

        if prev_addrs != new_addrs {
            prev_addrs = new_addrs;

            match addr_infos_from_p2p_addrs(&addrs) {
                Ok(infos) if infos.len() != 1 => {
                    tracing::error!(
                        n = infos.len(),
                        "Failed resolving a single relay ID from addresses"
                    );
                }
                Ok(infos) => {
                    let peer = Peer::new_relay_peer(&infos[0]);
                    info!(
                        peer = %peer.name,
                        url = %raw_url,
                        addrs = ?peer.addresses,
                        "Resolved new relay"
                    );
                    if let Err(e) = mutable.set(peer) {
                        tracing::error!(err = %e, "Failed to set mutable peer");
                    }
                }
                Err(e) => {
                    tracing::error!(err = %e, addrs = ?addrs, "Failed resolving relay ID from addresses");
                }
            }
        }

        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(RELAY_POLL_INTERVAL) => {}
        }
    }
}

/// Returns the relay multiaddrs via an HTTP GET query to the URL.
///
/// This supports resolving relay addrs from known HTTP URLs which is handy
/// when relays are deployed in docker compose or kubernetes.
///
/// It retries until success or cancellation.
async fn query_relay_addrs(
    cancel: CancellationToken,
    client: &reqwest::Client,
    relay_url: &str,
    lock_hash_hex: &str,
) -> Result<Vec<Multiaddr>> {
    let parsed_url = url::Url::parse(relay_url)?;
    let scheme = parsed_url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(BootnodeError::InvalidRelayUrl);
    }

    // Retry with exponential backoff
    let backoff = ExponentialBuilder::default()
        .with_min_delay(FAST_BASE_DELAY)
        .with_max_delay(FAST_MAX_DELAY)
        .with_factor(FAST_MULTIPLIER)
        .with_jitter();

    let fetch = || async {
        if cancel.is_cancelled() {
            return Err(BootnodeError::TimeoutQueryingRelayAddresses);
        }

        let resp = client
            .get(relay_url)
            .header("Charon-Cluster", lock_hash_hex)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(err = %e, "Failure querying relay addresses (will try again)");
                BootnodeError::NewRequest(e)
            })?;

        if !resp.status().is_success() {
            tracing::warn!(
                status_code = resp.status().as_u16(),
                "Non-200 response querying relay addresses (will try again)"
            );
            return Err(BootnodeError::InvalidRelayUrl);
        }

        let body = resp.text().await.map_err(|e| {
            tracing::warn!(err = %e, "Failure reading relay addresses (will try again)");
            BootnodeError::NewRequest(e)
        })?;

        if body.starts_with("enr:") {
            match multi_addr_from_enr_str(&body) {
                Ok(addrs) => return Ok(addrs),
                Err(e) => {
                    tracing::warn!(err = %e, "Failure parsing relay address from ENR (will try again)");
                    return Err(e);
                }
            }
        }

        let addrs: Vec<String> = serde_json::from_str(&body).map_err(|e| {
            tracing::warn!(err = %e, "Failure parsing relay addresses json (will try again)");
            BootnodeError::InvalidRelayUrl
        })?;

        let mut maddrs = Vec::new();
        for addr_str in &addrs {
            match addr_str.parse::<Multiaddr>() {
                Ok(maddr) => maddrs.push(maddr),
                Err(e) => {
                    tracing::warn!(err = %e, addr = %addr_str, "Failure parsing relay multiaddrs (will try again)");
                }
            }
        }

        Ok(maddrs)
    };

    // Using backon for retry
    let retry_condition = |e: &BootnodeError| {
        // Don't retry on cancellation
        !matches!(e, BootnodeError::TimeoutQueryingRelayAddresses)
    };

    fetch.retry(backoff).when(retry_condition).await
}

/// Returns multiaddrs from an ENR string.
///
/// Creates QUIC-v1 multiaddr if UDP port is present, and TCP multiaddr if TCP
/// port is present.
pub fn multi_addr_from_enr_str(enr_str: &str) -> Result<Vec<Multiaddr>> {
    let record = Record::try_from(enr_str)?;

    let ip = record.ip().ok_or(BootnodeError::EnrNoIp)?;

    let public_key = record.public_key.ok_or(BootnodeError::GetPeerIdFromEnrKey(
        PeerError::MissingPublicKeyInEnr,
    ))?;

    let peer_id = peer_id_from_key(public_key)?;

    let mut addrs = Vec::new();

    // Create QUIC-v1 multiaddr if UDP port is present
    if let Some(udp_port) = record.udp() {
        let addr: Multiaddr = format!("/ip4/{ip}/udp/{udp_port}/quic-v1/p2p/{peer_id}")
            .parse()
            .map_err(BootnodeError::CreateQuicMultiaddr)?;
        addrs.push(addr);
    }

    // Create TCP multiaddr if TCP port is present
    if let Some(tcp_port) = record.tcp() {
        let addr: Multiaddr = format!("/ip4/{ip}/tcp/{tcp_port}/p2p/{peer_id}")
            .parse()
            .map_err(BootnodeError::CreateTcpMultiaddr)?;
        addrs.push(addr);
    }

    if addrs.is_empty() {
        return Err(BootnodeError::EnrNoPort);
    }

    Ok(addrs)
}

/// Extracts AddrInfo from a single P2P multiaddr.
///
/// This is a convenience wrapper around `addr_infos_from_p2p_addrs` for a
/// single address.
fn addr_info_from_p2p_addr(addr: &Multiaddr) -> std::result::Result<AddrInfo, PeerError> {
    let mut infos = addr_infos_from_p2p_addrs(std::slice::from_ref(addr))?;

    infos.pop().ok_or(PeerError::MissingPeerIdInMultiaddr)
}
