//! Bootnode and relay resolution functionality.

use std::time::Duration;

use backon::Retryable;
use libp2p::Multiaddr;
use pluto_eth2util::enr::Record;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use url::Url;

use crate::{
    config::RelayAddr,
    peer::{AddrInfo, MutablePeer, Peer, PeerError, addr_infos_from_p2p_addrs, peer_id_from_key},
};

/// Polling interval for relay address updates.
const RELAY_POLL_INTERVAL: Duration = Duration::from_secs(120); // 2 minutes

/// Timeout for resolving at least one bootnode ENR.
const BOOTNODE_RESOLVE_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval for checking bootnode resolution status.
const BOOTNODE_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Per-request timeout for relay address queries.
const RELAY_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum relay-address response body read from a relay (1 MB). The response
/// is an ENR string or a small JSON list of multiaddrs; 1 MB is generous while
/// bounding memory against a hostile relay.
const RELAY_MAX_BODY: usize = 1024 * 1024;

/// Bootnode error.
#[derive(Debug, thiserror::Error)]
pub enum BootnodeError {
    /// Failed to get peer from multiaddr.
    #[error("peer from multiaddr: {0}")]
    PeerFromMultiaddr(String),

    /// A relay address query failed and should be retried.
    #[error("relay address query failed")]
    RelayQueryFailed,

    /// The relay URL scheme is neither `http` nor `https`.
    #[error("invalid relay url: {0}")]
    InvalidRelayUrl(String),

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

    /// Relay address response body exceeded the allowed size.
    #[error("relay address body exceeds {0} bytes")]
    BodyTooLarge(usize),
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
    relays: &[RelayAddr],
    lock_hash_hex: &str,
) -> Result<Vec<MutablePeer>> {
    let mut resp = Vec::new();

    for relay_addr in relays {
        match relay_addr {
            RelayAddr::Url(url) => {
                if relay_addr.is_insecure_url() {
                    warn!(addr = %url, "Relay URL does not use https protocol");
                }

                let mutable = MutablePeer::default();
                let url = url.clone();
                let hash = lock_hash_hex.to_string();
                let mutable_clone = mutable.clone();
                let cancel_clone = cancel.child_token();

                tokio::spawn(async move {
                    resolve_relay(cancel_clone, url, hash, mutable_clone).await;
                });

                resp.push(mutable);
            }
            RelayAddr::Multiaddr(addr) => {
                let info = addr_info_from_p2p_addr(addr)
                    .map_err(|_| BootnodeError::PeerFromMultiaddr(addr.to_string()))?;

                resp.push(MutablePeer::new(Peer::new_relay_peer(&info)));
            }
        }
    }

    if resp.is_empty() {
        return Ok(resp);
    }

    let resp = tokio::time::timeout(BOOTNODE_RESOLVE_TIMEOUT, async {
        loop {
            if cancel.is_cancelled() {
                return Err(BootnodeError::TimeoutResolvingBootnodeEnr);
            }

            let resolved = resp.iter().any(|node| node.peer().is_some());

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
    relay_url: Url,
    lock_hash_hex: String,
    mutable: MutablePeer,
) {
    let mut prev_addrs = String::new();
    let client = reqwest::Client::builder()
        .timeout(RELAY_QUERY_TIMEOUT)
        .build()
        .unwrap_or_default();

    loop {
        if cancel.is_cancelled() {
            return;
        }

        let addrs = match query_relay_addrs(cancel.clone(), &client, &relay_url, &lock_hash_hex)
            .await
        {
            Ok(addrs) => addrs,
            Err(e) => {
                tracing::error!(err = %e, url = %relay_url, "Failed resolving relay addresses from URL");
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
                        url = %relay_url,
                        addrs = ?peer.addresses,
                        "Resolved new relay"
                    );
                    mutable.set(peer);
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
    relay_url: &Url,
    lock_hash_hex: &str,
) -> Result<Vec<Multiaddr>> {
    // `RelayAddr::from_str` already enforces this, but the variant is publicly
    // constructible, so re-check at the point of use — and before the retry
    // loop, since an unsupported scheme is not transient and would otherwise
    // retry until cancellation instead of failing fast.
    if !matches!(relay_url.scheme(), "http" | "https") {
        return Err(BootnodeError::InvalidRelayUrl(relay_url.to_string()));
    }

    // Retry with exponential backoff until the cancel token fires, matching
    // Go's `queryRelayAddrs` ("It retries until the context is cancelled").
    let backoff = pluto_core::expbackoff::fast();

    let fetch = || async {
        if cancel.is_cancelled() {
            return Err(BootnodeError::TimeoutQueryingRelayAddresses);
        }

        let resp = client
            .get(relay_url.clone())
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
            return Err(BootnodeError::RelayQueryFailed);
        }

        let body = read_relay_body_capped(resp, RELAY_MAX_BODY).await?;

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
            BootnodeError::RelayQueryFailed
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

/// Reads a relay response body as UTF-8, failing with
/// [`BootnodeError::BodyTooLarge`] if it would exceed `max` bytes. Streams so
/// the cap bounds memory even without a trustworthy `Content-Length` header.
async fn read_relay_body_capped(resp: reqwest::Response, max: usize) -> Result<String> {
    use futures::StreamExt;

    if let Some(len) = resp.content_length()
        && len > max as u64
    {
        tracing::warn!(len, max, "Relay address body too large (will try again)");
        return Err(BootnodeError::BodyTooLarge(max));
    }

    let mut buf = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            tracing::warn!(err = %e, "Failure reading relay addresses (will try again)");
            BootnodeError::NewRequest(e)
        })?;
        if buf.len().saturating_add(chunk.len()) > max {
            tracing::warn!(max, "Relay address body too large (will try again)");
            return Err(BootnodeError::BodyTooLarge(max));
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
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

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::rand_core::OsRng;
    use libp2p::PeerId;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::*;

    const LOCK_HASH: &str = "0badcafe";

    /// Returns a random relay peer ID together with the multiaddr JSON body a
    /// relay serves for it.
    fn relay_fixture() -> (PeerId, String) {
        let key = k256::SecretKey::random(&mut OsRng);
        let peer_id = peer_id_from_key(key.public_key()).expect("peer id from key");
        let body = serde_json::to_string(&[format!("/ip4/10.0.0.1/tcp/3610/p2p/{peer_id}")])
            .expect("serialize relay addrs");

        (peer_id, body)
    }

    /// Starts a relay stub serving `body` at `relay_path`. Any other path 404s,
    /// so a request that loses the path fails the test rather than silently
    /// resolving against the root.
    async fn relay_server(relay_path: &str, body: String) -> MockServer {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(relay_path))
            .and(header("Charon-Cluster", LOCK_HASH))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        server
    }

    /// Resolves `relay` and returns the single relay peer ID it yields.
    async fn resolve_one(relay: &str) -> PeerId {
        let relay: RelayAddr = relay.parse().expect("relay addr should parse");
        let cancel = CancellationToken::new();

        let relays = new_relays(cancel.clone(), &[relay], LOCK_HASH)
            .await
            .expect("relays should resolve");
        cancel.cancel();

        assert_eq!(relays.len(), 1);

        relays[0].peer().expect("relay should be resolved").id
    }

    #[tokio::test]
    async fn new_relays_resolves_url_with_path() {
        let (peer_id, body) = relay_fixture();
        let server = relay_server("/enr", body).await;

        assert_eq!(resolve_one(&format!("{}/enr", server.uri())).await, peer_id);
    }

    #[tokio::test]
    async fn new_relays_resolves_url_without_path() {
        let (peer_id, body) = relay_fixture();
        let server = relay_server("/", body).await;

        assert_eq!(resolve_one(&server.uri()).await, peer_id);
    }

    #[tokio::test]
    async fn new_relays_resolves_raw_multiaddr() {
        let (peer_id, _) = relay_fixture();

        assert_eq!(
            resolve_one(&format!("/ip4/10.0.0.1/tcp/3610/p2p/{peer_id}")).await,
            peer_id
        );
    }

    #[tokio::test]
    async fn new_relays_rejects_multiaddr_without_peer_id() {
        let relay: RelayAddr = "/ip4/10.0.0.1/tcp/3610".parse().expect("relay addr");

        let err = new_relays(CancellationToken::new(), &[relay], LOCK_HASH)
            .await
            .expect_err("multiaddr without a peer ID should be rejected");

        assert!(matches!(err, BootnodeError::PeerFromMultiaddr(_)));
    }

    #[tokio::test]
    async fn new_relays_without_relays_is_empty() {
        let relays = new_relays(CancellationToken::new(), &[], LOCK_HASH)
            .await
            .expect("no relays should resolve");

        assert!(relays.is_empty());
    }

    #[tokio::test]
    async fn query_relay_addrs_rejects_unsupported_scheme() {
        // `RelayAddr::Url` is publicly constructible, so a non-HTTP(S) URL can
        // reach here; it must fail fast rather than retry until cancellation.
        let err = query_relay_addrs(
            CancellationToken::new(),
            &reqwest::Client::new(),
            &"ftp://relay.example.org".parse().expect("url"),
            LOCK_HASH,
        )
        .await
        .expect_err("unsupported scheme should not be queried");

        assert!(
            matches!(err, BootnodeError::InvalidRelayUrl(_)),
            "unexpected error: {err}"
        );
    }
}
