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

use chrono::{DateTime, Utc};
use libp2p::{PeerId, swarm::Stream};
use pluto_core::version::{self, SemVer, SemVerError};
use pluto_p2p::proto::MAX_MESSAGE_SIZE;
use regex::Regex;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::{
    LocalPeerInfo,
    metrics::{PEERINFO_METRICS, PeerGitHashLabels, PeerNicknameLabels, PeerVersionLabels},
    peerinfopb::v1::peerinfo::PeerInfo,
};

static GIT_HASH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{7}$").expect("invalid regex"));

const PEERINFO_MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// State of the protocol.
pub struct ProtocolState {
    /// The peer ID.
    peer_id: PeerId,

    /// The peer name.
    name: String,

    nicknames: Arc<Mutex<HashMap<String, String>>>,

    local_info: LocalPeerInfo,
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
        let name = pluto_p2p::name::peer_name(&peer_id);
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
            let mut nicknames = self.nicknames.lock().await;
            let prev_nickname = nicknames.insert(self.name.clone(), peer_info.nickname.clone());

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

        if supported_peer_version(&peer_info.pluto_version, version::SUPPORTED).is_err() {
            PEERINFO_METRICS.version_support[&self.name].set(0);

            tracing::error!(peer = self.name, peer_version = peer_info.pluto_version, supported_versions = ?version::SUPPORTED, "Invalid peer version");

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
            &peer_info.pluto_version,
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
        let peer_name = pluto_p2p::name::peer_name(&self.peer_id);

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
        pluto_p2p::proto::write_protobuf(&mut stream, request).await?;
        let response =
            pluto_p2p::proto::read_protobuf_with_max_size(&mut stream, PEERINFO_MAX_MESSAGE_SIZE)
                .await?;
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
        let request =
            pluto_p2p::proto::read_protobuf_with_max_size(&mut stream, PEERINFO_MAX_MESSAGE_SIZE)
                .await?;
        pluto_p2p::proto::write_protobuf(&mut stream, local_info).await?;
        Ok((stream, request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use prost::Message;

    // Test case: minimal
    // CharonVersion: "v1.0.0"
    // LockHash: deadbeef
    // BuilderApiEnabled: false
    const PEERINFO_MINIMAL: &[u8] = &hex!("0a0676312e302e301204deadbeef");

    // Test case: with_git_hash
    // CharonVersion: "v1.7.1"
    // LockHash: 0000000000000000000000000000000000000000000000000000000000000000
    // GitHash: "abc1234"
    // BuilderApiEnabled: false
    const PEERINFO_WITH_GIT_HASH: &[u8] = &hex!(
        "0a0676312e372e3112200000000000000000000000000000000000000000000000000000000000000000220761626331323334"
    );

    // Test case: full
    // CharonVersion: "v1.7.1"
    // LockHash: 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
    // SentAt: 2025-01-15T12:30:45Z
    // GitHash: "a1b2c3d"
    // StartedAt: 2025-01-15T10:00:00Z
    // BuilderApiEnabled: true
    // Nickname: "test-node"
    const PEERINFO_FULL: &[u8] = &hex!(
        "0a0676312e372e3112200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f201a0608f5d49ebc062207613162326333642a0608a08e9ebc0630013a09746573742d6e6f6465"
    );

    // Test case: builder_disabled
    // CharonVersion: "v1.5.0"
    // LockHash: ffffffff
    // SentAt: 2024-12-01T00:00:00Z
    // GitHash: "1234567"
    // StartedAt: 2024-11-30T23:00:00Z
    // BuilderApiEnabled: false
    // Nickname: "validator-1"
    const PEERINFO_BUILDER_DISABLED: &[u8] = &hex!(
        "0a0676312e352e301204ffffffff1a060880ceaeba062207313233343536372a0608f0b1aeba063a0b76616c696461746f722d31"
    );

    // Test case: empty_optional_fields
    // CharonVersion: "v1.6.0"
    // LockHash: cafebabe
    // BuilderApiEnabled: false
    const PEERINFO_EMPTY_OPTIONAL_FIELDS: &[u8] = &hex!("0a0676312e362e301204cafebabe");

    #[test]
    fn git_hash_regex_correct() {
        assert!(GIT_HASH_RE.is_match("abc1234"));
    }

    /// Helper to create a PeerInfo with minimal fields
    fn make_minimal_peerinfo() -> PeerInfo {
        PeerInfo {
            pluto_version: "v1.0.0".to_string(),
            lock_hash: vec![0xde, 0xad, 0xbe, 0xef].into(),
            sent_at: None,
            git_hash: String::new(),
            started_at: None,
            builder_api_enabled: false,
            nickname: String::new(),
        }
    }

    /// Helper to create a PeerInfo with git hash
    fn make_with_git_hash_peerinfo() -> PeerInfo {
        PeerInfo {
            pluto_version: "v1.7.1".to_string(),
            lock_hash: vec![0u8; 32].into(),
            sent_at: None,
            git_hash: "abc1234".to_string(),
            started_at: None,
            builder_api_enabled: false,
            nickname: String::new(),
        }
    }

    /// Helper to create a full PeerInfo with all fields
    fn make_full_peerinfo() -> PeerInfo {
        PeerInfo {
            pluto_version: "v1.7.1".to_string(),
            lock_hash: (1u8..=32).collect::<Vec<_>>().into(),
            sent_at: Some(prost_types::Timestamp {
                seconds: 1736944245, // 2025-01-15T13:00:45Z
                nanos: 0,
            }),
            git_hash: "a1b2c3d".to_string(),
            started_at: Some(prost_types::Timestamp {
                seconds: 1736935200, // 2025-01-15T10:30:00Z
                nanos: 0,
            }),
            builder_api_enabled: true,
            nickname: "test-node".to_string(),
        }
    }

    /// Helper to create a PeerInfo with builder disabled
    fn make_builder_disabled_peerinfo() -> PeerInfo {
        PeerInfo {
            pluto_version: "v1.5.0".to_string(),
            lock_hash: vec![0xff, 0xff, 0xff, 0xff].into(),
            sent_at: Some(prost_types::Timestamp {
                seconds: 1733011200, // 2024-12-01T00:00:00Z
                nanos: 0,
            }),
            git_hash: "1234567".to_string(),
            started_at: Some(prost_types::Timestamp {
                seconds: 1733007600, // 2024-11-30T23:00:00Z
                nanos: 0,
            }),
            builder_api_enabled: false,
            nickname: "validator-1".to_string(),
        }
    }

    /// Helper to create a PeerInfo with empty optional fields
    fn make_empty_optional_peerinfo() -> PeerInfo {
        PeerInfo {
            pluto_version: "v1.6.0".to_string(),
            lock_hash: vec![0xca, 0xfe, 0xba, 0xbe].into(),
            sent_at: None,
            git_hash: String::new(),
            started_at: None,
            builder_api_enabled: false,
            nickname: String::new(),
        }
    }

    #[test]
    fn decode_minimal() {
        let decoded = PeerInfo::decode(PEERINFO_MINIMAL).unwrap();
        let expected = make_minimal_peerinfo();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn decode_with_git_hash() {
        let decoded = PeerInfo::decode(PEERINFO_WITH_GIT_HASH).unwrap();
        let expected = make_with_git_hash_peerinfo();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn decode_full() {
        let decoded = PeerInfo::decode(PEERINFO_FULL).unwrap();
        let expected = make_full_peerinfo();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn decode_builder_disabled() {
        let decoded = PeerInfo::decode(PEERINFO_BUILDER_DISABLED).unwrap();
        let expected = make_builder_disabled_peerinfo();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn decode_empty_optional_fields() {
        let decoded = PeerInfo::decode(PEERINFO_EMPTY_OPTIONAL_FIELDS).unwrap();
        let expected = make_empty_optional_peerinfo();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn encode_minimal() {
        let msg = make_minimal_peerinfo();
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf, PEERINFO_MINIMAL);
    }

    #[test]
    fn encode_with_git_hash() {
        let msg = make_with_git_hash_peerinfo();
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf, PEERINFO_WITH_GIT_HASH);
    }

    #[test]
    fn encode_full() {
        let msg = make_full_peerinfo();
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf, PEERINFO_FULL);
    }

    #[test]
    fn encode_builder_disabled() {
        let msg = make_builder_disabled_peerinfo();
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf, PEERINFO_BUILDER_DISABLED);
    }

    #[test]
    fn encode_empty_optional_fields() {
        let msg = make_empty_optional_peerinfo();
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf, PEERINFO_EMPTY_OPTIONAL_FIELDS);
    }

    #[test]
    fn roundtrip_all_variants() {
        let variants = [
            make_minimal_peerinfo(),
            make_with_git_hash_peerinfo(),
            make_full_peerinfo(),
            make_builder_disabled_peerinfo(),
            make_empty_optional_peerinfo(),
        ];

        for original in variants {
            let mut buf = Vec::new();
            original.encode(&mut buf).unwrap();
            let decoded = PeerInfo::decode(&buf[..]).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[tokio::test]
    async fn write_read_protobuf_minimal() {
        let original = make_minimal_peerinfo();

        // Write to a cursor
        let mut buf = Vec::new();
        pluto_p2p::proto::write_protobuf(&mut buf, &original)
            .await
            .unwrap();

        // The wire format should be: [varint length][protobuf bytes]
        // Minimal message is 14 bytes, so length prefix is just 1 byte (14 < 128)
        assert_eq!(buf[0] as usize, PEERINFO_MINIMAL.len());
        assert_eq!(&buf[1..], PEERINFO_MINIMAL);

        // Read it back
        let mut cursor = futures::io::Cursor::new(&buf[..]);
        let decoded: PeerInfo =
            pluto_p2p::proto::read_protobuf_with_max_size(&mut cursor, PEERINFO_MAX_MESSAGE_SIZE)
                .await
                .unwrap();
        assert_eq!(original, decoded);
    }

    #[tokio::test]
    async fn write_read_protobuf_full() {
        let original = make_full_peerinfo();

        let mut buf = Vec::new();
        pluto_p2p::proto::write_protobuf(&mut buf, &original)
            .await
            .unwrap();

        // Read it back
        let mut cursor = futures::io::Cursor::new(&buf[..]);
        let decoded: PeerInfo =
            pluto_p2p::proto::read_protobuf_with_max_size(&mut cursor, PEERINFO_MAX_MESSAGE_SIZE)
                .await
                .unwrap();
        assert_eq!(original, decoded);
    }

    #[tokio::test]
    async fn write_read_protobuf_all_variants() {
        let variants = [
            make_minimal_peerinfo(),
            make_with_git_hash_peerinfo(),
            make_full_peerinfo(),
            make_builder_disabled_peerinfo(),
            make_empty_optional_peerinfo(),
        ];

        for original in variants {
            let mut buf = Vec::new();
            pluto_p2p::proto::write_protobuf(&mut buf, &original)
                .await
                .unwrap();

            let mut cursor = futures::io::Cursor::new(&buf[..]);
            let decoded: PeerInfo = pluto_p2p::proto::read_protobuf_with_max_size(
                &mut cursor,
                PEERINFO_MAX_MESSAGE_SIZE,
            )
            .await
            .unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[tokio::test]
    async fn read_protobuf_message_too_large() {
        // Create a buffer with a length prefix that exceeds MAX_MESSAGE_SIZE
        let mut buf = Vec::new();
        let large_len = PEERINFO_MAX_MESSAGE_SIZE + 1;
        let mut len_buf: [u8; 10] = unsigned_varint::encode::usize_buffer();
        let encoded_len = unsigned_varint::encode::usize(large_len, &mut len_buf);
        buf.extend_from_slice(encoded_len);

        let mut cursor = futures::io::Cursor::new(&buf[..]);
        let result: io::Result<PeerInfo> =
            pluto_p2p::proto::read_protobuf_with_max_size(&mut cursor, PEERINFO_MAX_MESSAGE_SIZE)
                .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("message too large"));
    }

    #[tokio::test]
    async fn read_protobuf_invalid_data() {
        // Create a buffer with valid length but invalid protobuf data
        let invalid_data = [0x05, 0xff, 0xff, 0xff, 0xff, 0xff]; // length 5, then garbage

        let mut cursor = futures::io::Cursor::new(&invalid_data[..]);
        let result: io::Result<PeerInfo> =
            pluto_p2p::proto::read_protobuf_with_max_size(&mut cursor, PEERINFO_MAX_MESSAGE_SIZE)
                .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_protobuf_truncated_message() {
        // Create a buffer that claims a length but doesn't have enough bytes
        let truncated = [0x10]; // claims 16 bytes but has none

        let mut cursor = futures::io::Cursor::new(&truncated[..]);
        let result: io::Result<PeerInfo> =
            pluto_p2p::proto::read_protobuf_with_max_size(&mut cursor, PEERINFO_MAX_MESSAGE_SIZE)
                .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn multiple_messages_in_stream() {
        let msg1 = make_minimal_peerinfo();
        let msg2 = make_full_peerinfo();
        let msg3 = make_with_git_hash_peerinfo();

        // Write multiple messages to the same buffer
        let mut buf = Vec::new();
        pluto_p2p::proto::write_protobuf(&mut buf, &msg1)
            .await
            .unwrap();
        pluto_p2p::proto::write_protobuf(&mut buf, &msg2)
            .await
            .unwrap();
        pluto_p2p::proto::write_protobuf(&mut buf, &msg3)
            .await
            .unwrap();

        // Read them back in order
        let mut cursor = futures::io::Cursor::new(&buf[..]);
        let decoded1: PeerInfo =
            pluto_p2p::proto::read_protobuf_with_max_size(&mut cursor, PEERINFO_MAX_MESSAGE_SIZE)
                .await
                .unwrap();
        let decoded2: PeerInfo =
            pluto_p2p::proto::read_protobuf_with_max_size(&mut cursor, PEERINFO_MAX_MESSAGE_SIZE)
                .await
                .unwrap();
        let decoded3: PeerInfo =
            pluto_p2p::proto::read_protobuf_with_max_size(&mut cursor, PEERINFO_MAX_MESSAGE_SIZE)
                .await
                .unwrap();

        assert_eq!(msg1, decoded1);
        assert_eq!(msg2, decoded2);
        assert_eq!(msg3, decoded3);
    }
}
