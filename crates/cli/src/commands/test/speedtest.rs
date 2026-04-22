//! Ookla Speedtest.net client for latency, download, and upload measurements.

use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::error::{CliError, Result};

const SPEEDTEST_SERVERS_URL: &str =
    "https://www.speedtest.net/api/js/servers?engine=js&https_functional=true&limit=10";
const SPEEDTEST_MAX_CANDIDATES: usize = 5;
const SPEEDTEST_UPLOAD_BYTES: usize = 50_000_000;

#[derive(Deserialize)]
struct OoklaServerResponse {
    id: String,
    name: String,
    country: String,
    url: String,
    #[serde(default)]
    distance: f64,
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
        self.url.strip_suffix("upload.php").unwrap_or(&self.url)
    }

    pub(super) async fn ping_test(&mut self, client: &reqwest::Client) -> Result<()> {
        let latency_url = format!("{}latency.txt", self.base_url());
        let start = Instant::now();
        // Read and discard the body so the connection is left in a clean state
        // for the connection pool; dropping Response without reading closes the
        // underlying TCP socket and corrupts pool state for subsequent requests.
        let response = client.get(&latency_url).send().await?;
        let _ = response.bytes().await?;
        self.latency = start.elapsed();
        Ok(())
    }

    pub(super) async fn download_test(&mut self, client: &reqwest::Client) -> Result<()> {
        // Download multiple large images sequentially to saturate the link long enough
        // for an accurate throughput measurement (single 4000x4000 JPEG is ~4MB).
        let download_url = format!("{}random4000x4000.jpg", self.base_url());
        let mut total_bytes = 0usize;
        let start = Instant::now();
        for _ in 0..4 {
            let response = client.get(&download_url).send().await?;
            if !response.status().is_success() {
                return Err(CliError::Other(format!(
                    "download test failed: HTTP {}",
                    response.status()
                )));
            }
            total_bytes = total_bytes.saturating_add(response.bytes().await?.len());
        }
        self.dl_speed_mbps = bytes_to_mbps(total_bytes, start.elapsed());
        Ok(())
    }

    pub(super) async fn upload_test(&mut self, client: &reqwest::Client) -> Result<()> {
        let upload_data = vec![0u8; SPEEDTEST_UPLOAD_BYTES];
        let start = Instant::now();
        let response = client
            .post(&self.url)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", SPEEDTEST_UPLOAD_BYTES.to_string())
            .body(upload_data)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(CliError::Other(format!(
                "upload test failed: HTTP {}",
                response.status()
            )));
        }
        let _ = response.bytes().await?;
        self.ul_speed_mbps = bytes_to_mbps(SPEEDTEST_UPLOAD_BYTES, start.elapsed());
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

/// Fetches the Ookla server list, applies filters, pings candidates, and
/// returns the lowest-latency reachable server.
pub(super) async fn fetch_best_server(
    servers_only: &[String],
    servers_exclude: &[String],
    client: &reqwest::Client,
) -> Result<SpeedtestServer> {
    let servers: Vec<OoklaServerResponse> = client
        .get(SPEEDTEST_SERVERS_URL)
        .send()
        .await
        .map_err(|e| CliError::Other(format!("fetch Ookla servers: {e}")))?
        .json()
        .await
        .map_err(|e| CliError::Other(format!("fetch Ookla servers: {e}")))?;

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

    let mut best: Option<SpeedtestServer> = None;
    for candidate in candidates.into_iter().take(SPEEDTEST_MAX_CANDIDATES) {
        let mut server = SpeedtestServer::from_response(candidate);
        if server.ping_test(client).await.is_ok() {
            let is_better = best.as_ref().is_none_or(|b| server.latency < b.latency);
            if is_better {
                best = Some(server);
            }
        }
    }

    best.ok_or_else(|| CliError::Other("find Ookla server: no reachable servers".to_string()))
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
