//! Ookla Speedtest.net client for latency, download, and upload measurements.

use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::error::{CliError, Result};

const SPEEDTEST_SERVERS_URL: &str =
    "https://www.speedtest.net/api/js/servers?engine=js&https_functional=true&limit=10";
const SPEEDTEST_SERVERS_FALLBACK_URL: &str =
    "https://www.speedtest.net/speedtest-servers-static.php";
const FETCH_PING_TIMEOUT: Duration = Duration::from_secs(4);
const PING_COUNT: u32 = 10;
const PING_INTERVAL: Duration = Duration::from_millis(200);
const SPEED_TEST_DURATION: Duration = Duration::from_secs(15);
// Matches Go's ulSizes[4]=1000: chunkSize = (1000*100-51)*10
const UPLOAD_CHUNK_BYTES: usize = 999_490;

fn speed_test_concurrency() -> usize {
    match std::thread::available_parallelism() {
        Ok(n) => n.get(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to query CPU count, defaulting to 1 concurrent stream");
            1
        }
    }
}

#[derive(Deserialize)]
struct OoklaServerResponse {
    id: String,
    name: String,
    country: String,
    url: String,
    #[serde(default)]
    distance: f64,
}

#[derive(Deserialize)]
#[serde(rename = "settings")]
struct XmlServerList {
    servers: XmlServersWrapper,
}

#[derive(Deserialize)]
struct XmlServersWrapper {
    server: Vec<XmlServer>,
}

#[derive(Deserialize)]
struct XmlServer {
    #[serde(rename = "@url")]
    url: String,
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@country")]
    country: String,
    #[serde(rename = "@id")]
    id: String,
}

impl From<XmlServer> for OoklaServerResponse {
    fn from(s: XmlServer) -> Self {
        Self {
            id: s.id,
            name: s.name,
            country: s.country,
            url: s.url,
            distance: 0.0,
        }
    }
}

pub(super) struct SpeedtestServer {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) country: String,
    pub(super) distance: f64,
    pub(super) latency: Duration,
    pub(super) dl_speed_mbps: f64,
    pub(super) ul_speed_mbps: f64,
    url: String,
}

impl SpeedtestServer {
    fn from_response(r: OoklaServerResponse) -> Self {
        Self {
            id: r.id,
            name: r.name,
            country: r.country,
            url: r.url,
            distance: r.distance,
            latency: Duration::ZERO,
            dl_speed_mbps: 0.0,
            ul_speed_mbps: 0.0,
        }
    }

    fn base_url(&self) -> &str {
        match self.url.strip_suffix("upload.php") {
            Some(base) => base,
            None => {
                tracing::warn!(url = %self.url, "Ookla server URL does not end in 'upload.php'; subsequent requests may fail");
                &self.url
            }
        }
    }

    async fn quick_ping(&mut self, client: &reqwest::Client) -> Result<()> {
        let latency_url = format!("{}latency.txt", self.base_url());
        let start = Instant::now();
        let response = client.get(&latency_url).send().await?;
        // Read and discard the body so the connection is left in a clean state
        // for the connection pool; dropping Response without reading closes the
        // underlying TCP socket and corrupts pool state for subsequent requests.
        let _ = response.bytes().await?;
        self.latency = start.elapsed();
        Ok(())
    }

    pub(super) async fn ping_test(&mut self, client: &reqwest::Client) -> Result<()> {
        let latency_url = format!("{}latency.txt", self.base_url());
        let mut samples = Vec::with_capacity(PING_COUNT as usize);
        let mut ticker = tokio::time::interval(PING_INTERVAL);
        for _ in 0..PING_COUNT {
            ticker.tick().await;
            let start = Instant::now();
            let response = client.get(&latency_url).send().await?;
            let _ = response.bytes().await?;
            samples.push(start.elapsed());
        }
        let total: Duration = samples.iter().sum();
        self.latency = total
            .checked_div(PING_COUNT)
            .expect("PING_COUNT is non-zero");
        Ok(())
    }

    pub(super) async fn download_test(&mut self, client: &reqwest::Client) -> Result<()> {
        let download_url = format!("{}random1000x1000.jpg", self.base_url());
        let start = Instant::now();
        let deadline = start
            .checked_add(SPEED_TEST_DURATION)
            .expect("deadline does not overflow");

        // Go measures throughput via a Welford EWMA sampled every 50ms. Here we use
        // total_bytes/elapsed, which is simpler but equally valid for a single
        // measurement.
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..speed_test_concurrency() {
            let client = client.clone();
            let url = download_url.clone();
            set.spawn(async move {
                let mut bytes: usize = 0;
                while Instant::now() < deadline {
                    let Ok(resp) = client.get(&url).send().await else {
                        break;
                    };
                    if !resp.status().is_success() {
                        break;
                    }
                    if let Ok(body) = resp.bytes().await {
                        bytes = bytes
                            .checked_add(body.len())
                            .expect("download byte count does not overflow");
                    }
                }
                bytes
            });
        }

        let total_bytes: usize = set.join_all().await.into_iter().sum();
        self.dl_speed_mbps = bytes_to_mbps(total_bytes, start.elapsed());
        Ok(())
    }

    pub(super) async fn upload_test(&mut self, client: &reqwest::Client) -> Result<()> {
        let upload_url = self.url.clone();
        let start = Instant::now();
        let deadline = start
            .checked_add(SPEED_TEST_DURATION)
            .expect("deadline does not overflow");

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..speed_test_concurrency() {
            let client = client.clone();
            let url = upload_url.clone();
            set.spawn(async move {
                let mut bytes: usize = 0;
                while Instant::now() < deadline {
                    let chunk = vec![0u8; UPLOAD_CHUNK_BYTES];
                    let Ok(resp) = client
                        .post(&url)
                        .header("Content-Type", "application/octet-stream")
                        .body(chunk)
                        .send()
                        .await
                    else {
                        break;
                    };
                    if !resp.status().is_success() {
                        break;
                    }
                    let _ = resp.bytes().await;
                    bytes = bytes
                        .checked_add(UPLOAD_CHUNK_BYTES)
                        .expect("upload byte count does not overflow");
                }
                bytes
            });
        }

        let total_bytes: usize = set.join_all().await.into_iter().sum();
        self.ul_speed_mbps = bytes_to_mbps(total_bytes, start.elapsed());
        Ok(())
    }
}

/// Builds a shared reqwest client configured for Ookla Speedtest servers.
pub(super) fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("showwin/speedtest-go 1.7.10")
        .build()
        .map_err(|e| CliError::Other(format!("build HTTP client: {e}")))
}

async fn fetch_server_list(client: &reqwest::Client) -> Result<Vec<OoklaServerResponse>> {
    let response = client
        .get(SPEEDTEST_SERVERS_URL)
        .send()
        .await
        .map_err(|e| CliError::Other(format!("fetch Ookla servers: {e}")))?;

    if response.content_length() == Some(0) {
        return fetch_server_list_xml(client).await;
    }

    response
        .json()
        .await
        .map_err(|e| CliError::Other(format!("fetch Ookla servers: {e}")))
}

async fn fetch_server_list_xml(client: &reqwest::Client) -> Result<Vec<OoklaServerResponse>> {
    let body = client
        .get(SPEEDTEST_SERVERS_FALLBACK_URL)
        .send()
        .await
        .map_err(|e| CliError::Other(format!("fetch Ookla servers (XML fallback): {e}")))?
        .bytes()
        .await
        .map_err(|e| CliError::Other(format!("fetch Ookla servers (XML fallback): {e}")))?;

    let list: XmlServerList = quick_xml::de::from_reader(body.as_ref())
        .map_err(|e| CliError::Other(format!("parse Ookla servers XML: {e}")))?;

    Ok(list
        .servers
        .server
        .into_iter()
        .map(OoklaServerResponse::from)
        .collect())
}

/// Fetches the Ookla server list, applies filters, pings all candidates
/// concurrently, and returns the lowest-latency reachable server.
pub(super) async fn fetch_best_server(
    servers_only: &[String],
    servers_exclude: &[String],
    client: &reqwest::Client,
) -> Result<SpeedtestServer> {
    let servers = fetch_server_list(client).await?;

    // Go bug parity: the original Go implementation (testinfra.go) appends both
    // servers_only and servers_exclude filter results independently (union), so
    // excluded servers can still appear if they also match servers_only. The Rust
    // implementation correctly chains the filters as intersection, which is the
    // intended behaviour. This intentional divergence from Go is kept.
    let candidates: Vec<_> = servers
        .into_iter()
        .filter(|s| servers_only.is_empty() || servers_only.contains(&s.name))
        .filter(|s| !servers_exclude.contains(&s.name))
        .collect();

    if candidates.is_empty() {
        return Err(CliError::Other(
            "fetch Ookla servers: no servers match the specified filters".to_string(),
        ));
    }

    let ping_futures: Vec<_> = candidates
        .into_iter()
        .map(|r| {
            let client = client.clone();
            async move {
                let mut server = SpeedtestServer::from_response(r);
                let result =
                    tokio::time::timeout(FETCH_PING_TIMEOUT, server.quick_ping(&client)).await;
                match result {
                    Ok(Ok(())) => Some(server),
                    _ => None,
                }
            }
        })
        .collect();

    let mut reachable: Vec<SpeedtestServer> = futures::future::join_all(ping_futures)
        .await
        .into_iter()
        .flatten()
        .collect();

    reachable.sort_by_key(|s| s.latency);
    reachable
        .into_iter()
        .next()
        .ok_or_else(|| CliError::Other("find Ookla server: no reachable servers".to_string()))
}

pub(super) fn bytes_to_mbps(bytes: usize, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs == 0.0 {
        return 0.0;
    }

    #[allow(
        clippy::cast_precision_loss,
        clippy::arithmetic_side_effects,
        reason = "precision loss requires >8PB transferred; arithmetic overflow is impossible for realistic network speeds"
    )]
    let bytes: f64 = bytes as f64;
    bytes * 8.0 / secs / 1_000_000.0
}
