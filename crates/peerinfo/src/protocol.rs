//! Wire protocol implementation for the peerinfo protocol.
//!
//! This module handles encoding and decoding of PeerInfo messages on the wire
//! using the same format as Go's libp2p pbio package:
//!
//! ```text
//! [unsigned varint length][protobuf bytes]
//! ```
//!
//! The unsigned varint encoding uses 7 bits per byte for data, with the MSB
//! as a continuation flag (1 = more bytes follow, 0 = last byte).
use std::{
    collections::HashMap,
    io,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use charon_core::version::{self, SemVer, SemVerError};
use chrono::{DateTime, Utc};
use futures::prelude::*;
use libp2p::{PeerId, swarm::Stream};
use parking_lot::Mutex;
use prost::Message;
use regex::Regex;
use tracing::{info, warn};
use unsigned_varint::aio::read_usize;

use crate::{
    LocalPeerInfo,
    metrics::{PEERINFO_METRICS, PeerGitHashLabels, PeerNicknameLabels, PeerVersionLabels},
    peerinfopb::v1::peerinfo::PeerInfo,
};

/// Maximum message size (64KB should be plenty for peer info).
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

static GIT_HASH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{7}$").expect("invalid regex"));

/// State of the protocol.
pub struct ProtocolState {
    /// The peer ID.
    peer_id: PeerId,

    /// The peer name.
    name: String,

    nicknames: Arc<Mutex<HashMap<String, String>>>,

    local_info: LocalPeerInfo,
}

/// Writes a protobuf message with unsigned varint length prefix to the stream.
///
/// Wire format: `[uvarint length][protobuf bytes]`
async fn write_protobuf<M: Message>(stream: &mut Stream, msg: &M) -> io::Result<()> {
    // Encode message to protobuf bytes
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Write unsigned varint length prefix
    let mut len_buf = unsigned_varint::encode::usize_buffer();
    let encoded_len = unsigned_varint::encode::usize(buf.len(), &mut len_buf);
    stream.write_all(encoded_len).await?;

    // Write protobuf bytes
    stream.write_all(&buf).await?;
    stream.flush().await
}

/// Reads a protobuf message with unsigned varint length prefix from the stream.
///
/// Wire format: `[uvarint length][protobuf bytes]`
///
/// Returns an error if the message exceeds `MAX_MESSAGE_SIZE`.
async fn read_protobuf<M: Message + Default>(stream: &mut Stream) -> io::Result<M> {
    // Read unsigned varint length prefix
    let msg_len = read_usize(&mut *stream).await.map_err(|e| match e {
        unsigned_varint::io::ReadError::Io(io_err) => io_err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    })?;

    if msg_len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {msg_len} bytes (max: {MAX_MESSAGE_SIZE})"),
        ));
    }

    // Read exactly `msg_len` protobuf bytes
    let mut buf = vec![0u8; msg_len];
    stream.read_exact(&mut buf).await?;

    // Unmarshal protobuf
    M::decode(&buf[..]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Errors that can occur during the protocol.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Failed to parse peer version.
    #[error("Failed to parse peer version: {0}")]
    ParsePeerVersion(#[from] SemVerError),
    /// Unsupported peer version.
    #[error("Unsupported peer version {version}; coordinate with operator to align versions")]
    UnsupportedVersion {
        /// The unsupported peer version.
        version: String,
    },
}

fn supported_peer_version(version: &str, supported: &[SemVer]) -> Result<(), ProtocolError> {
    let peer_sem_ver = SemVer::parse(version)?;

    // Assume we are compatible with peers that are newer than us.
    if peer_sem_ver > supported[0] {
        return Ok(());
    }

    // Check if peer minor version matches any of our supported minor versions.
    if supported
        .iter()
        .any(|v| v.to_minor() == peer_sem_ver.to_minor())
    {
        return Ok(());
    }

    Err(ProtocolError::UnsupportedVersion {
        version: version.to_string(),
    })
}

impl ProtocolState {
    /// Creates a new protocol state.
    pub fn new(peer_id: PeerId, local_info: LocalPeerInfo) -> Self {
        let name = charon_p2p::name::peer_name(&peer_id);
        let mut nicknames = HashMap::new();
        nicknames.insert(name.clone(), local_info.nickname.clone());
        Self {
            peer_id,
            name,
            nicknames: Arc::new(Mutex::new(nicknames)),
            local_info,
        }
    }

    async fn validate_peer_info(&self, peer_info: &PeerInfo, rtt: Duration) {
        let Some(started_at) = peer_info.started_at else {
            warn!(
                peer = self.name,
                "Invalid peer info response: started at not provided"
            );
            return;
        };

        let Some(sent_at) = peer_info.sent_at else {
            warn!(
                peer = self.name,
                "Invalid peer info response: sent at not provided"
            );
            return;
        };

        let prev_nickname = {
            let mut nicknames = self.nicknames.lock();
            let prev_nickname = nicknames.get(&self.name).cloned();
            nicknames.insert(self.name.clone(), peer_info.nickname.clone());

            if prev_nickname.as_ref() != Some(&peer_info.nickname) {
                info!(nicknames = ?nicknames, "Peer name to nickname mappings");
            }

            prev_nickname
        };

        // Validator git hash with regex.
        if !GIT_HASH_RE.is_match(&peer_info.git_hash) {
            warn!(peer = self.name, "Invalid peer git hash");
            return;
        }

        #[allow(
            clippy::cast_precision_loss,
            clippy::arithmetic_side_effects,
            reason = "RTT/2 subtraction from current time cannot underflow"
        )]
        let expected_sent_at = chrono::Utc::now() - rtt / 2;
        let Some(actual_sent_at) = chrono::DateTime::<chrono::Utc>::from_timestamp(
            sent_at.seconds,
            u32::try_from(sent_at.nanos).unwrap_or(0),
        ) else {
            warn!(peer = self.name, sent_at = ?sent_at, "Invalid peer sent at");
            return;
        };
        let clock_offset = actual_sent_at.signed_duration_since(expected_sent_at);

        if supported_peer_version(&peer_info.charon_version, version::SUPPORTED).is_err() {
            PEERINFO_METRICS.version_support[&self.name].set(0);

            tracing::error!(peer = self.name, peer_version = peer_info.charon_version, supported_versions = ?version::SUPPORTED, "Invalid peer version");

            return;
        }

        // Set peer compatibility to true.
        PEERINFO_METRICS.version_support[&self.name].set(1);

        let Some(started_at) = chrono::DateTime::<chrono::Utc>::from_timestamp(
            started_at.seconds,
            u32::try_from(started_at.nanos).unwrap_or(0),
        ) else {
            warn!(peer = self.name, started_at = ?started_at, "Invalid peer started at");
            return;
        };

        self.metrics_submitter(
            clock_offset,
            &peer_info.charon_version,
            &peer_info.git_hash,
            started_at,
            peer_info.builder_api_enabled,
            &peer_info.nickname,
            prev_nickname.as_ref(),
        );

        // Log unexpected lock hash
        if peer_info.lock_hash != self.local_info.lock_hash {
            warn!(
                peer = self.name,
                lock_hash = hex::encode(&peer_info.lock_hash),
                "Mismatching peer lock hash"
            );
        }

        // Builder API shall be either enabled or disabled for both.
        if peer_info.builder_api_enabled != self.local_info.builder_api_enabled {
            warn!(
                peer = self.name,
                builder_api_enabled = peer_info.builder_api_enabled,
                "Mismatching peer builder API status"
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn metrics_submitter(
        &self,
        clock_offset: chrono::Duration,
        version: &str,
        git_hash: &str,
        start_time: DateTime<Utc>,
        builder_api_enabled: bool,
        nickname: &str,
        prev_nickname: Option<&String>,
    ) {
        let peer_name = charon_p2p::name::peer_name(&self.peer_id);

        // Reset previous peer nickname if it changed
        if let Some(prev) = prev_nickname {
            PEERINFO_METRICS.nickname[&PeerNicknameLabels::new(&peer_name, prev)].set(0);
        }
        PEERINFO_METRICS.nickname[&PeerNicknameLabels::new(&peer_name, nickname)].set(1);

        // Clamp clock offset to [-1 hour, 1 hour]
        let one_hour = chrono::Duration::hours(1);
        #[allow(clippy::arithmetic_side_effects)]
        let clamped_offset = if clock_offset < -one_hour {
            -one_hour
        } else if clock_offset > one_hour {
            one_hour
        } else {
            clock_offset
        };
        PEERINFO_METRICS.clock_offset_seconds[&peer_name].set(clamped_offset.num_seconds());

        // Set start time if not zero/epoch
        if start_time != DateTime::<Utc>::UNIX_EPOCH {
            PEERINFO_METRICS.start_time_secs[&peer_name].set(start_time.timestamp());
        }

        // Handle version - use "unknown" if empty
        let version = if version.is_empty() {
            "unknown"
        } else {
            version
        };
        PEERINFO_METRICS.version[&PeerVersionLabels::new(&peer_name, version)].set(1);

        // Handle git hash - use "unknown" if empty
        let git_hash = if git_hash.is_empty() {
            "unknown"
        } else {
            git_hash
        };
        PEERINFO_METRICS.git_commit[&PeerGitHashLabels::new(&peer_name, git_hash)].set(1);

        // Set builder API enabled gauge
        if builder_api_enabled {
            PEERINFO_METRICS.builder_api_enabled[&peer_name].set(1);
        } else {
            PEERINFO_METRICS.builder_api_enabled[&peer_name].set(0);
        }
    }

    /// Sends a peer info request and waits for a response.
    ///
    /// Returns the response `PeerInfo` on success.
    pub async fn send_peer_info(
        &self,
        mut stream: Stream,
        request: &PeerInfo,
    ) -> io::Result<(Stream, PeerInfo)> {
        let start = Instant::now();
        write_protobuf(&mut stream, request).await?;
        let response = read_protobuf(&mut stream).await?;
        let rtt = start.elapsed();

        self.validate_peer_info(&response, rtt).await;

        Ok((stream, response))
    }

    /// Receives a peer info request and sends a response.
    ///
    /// Returns the stream for potential reuse after successfully responding.
    pub async fn recv_peer_info(
        &self,
        mut stream: Stream,
        local_info: &PeerInfo,
    ) -> io::Result<(Stream, PeerInfo)> {
        let request = read_protobuf(&mut stream).await?;
        write_protobuf(&mut stream, local_info).await?;
        Ok((stream, request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_hash_regex_correct() {
        assert!(GIT_HASH_RE.is_match("abc1234"));
    }
}
