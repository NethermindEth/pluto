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

use std::io;

use futures::prelude::*;
use libp2p::swarm::Stream;
use prost::Message;
use unsigned_varint::aio::read_usize;

use crate::peerinfopb::v1::peerinfo::PeerInfo;

/// Maximum message size (64KB should be plenty for peer info).
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Writes a protobuf message with unsigned varint length prefix to the stream.
///
/// Wire format: `[uvarint length][protobuf bytes]`
async fn write_protobuf<M: Message, S: AsyncWrite + Unpin>(
    stream: &mut S,
    msg: &M,
) -> io::Result<()> {
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
async fn read_protobuf<M: Message + Default, S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<M> {
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

/// Sends a peer info request and waits for a response.
///
/// Returns the response `PeerInfo` on success.
pub async fn send_peer_info(
    mut stream: Stream,
    request: &PeerInfo,
) -> io::Result<(Stream, PeerInfo)> {
    write_protobuf(&mut stream, request).await?;
    let response = read_protobuf(&mut stream).await?;
    Ok((stream, response))
}

/// Receives a peer info request and sends a response.
///
/// Returns the stream for potential reuse after successfully responding.
pub async fn recv_peer_info(
    mut stream: Stream,
    local_info: &PeerInfo,
) -> io::Result<(Stream, PeerInfo)> {
    let request = read_protobuf(&mut stream).await?;
    write_protobuf(&mut stream, local_info).await?;
    Ok((stream, request))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

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

    /// Helper to create a PeerInfo with minimal fields
    fn make_minimal_peerinfo() -> PeerInfo {
        PeerInfo {
            charon_version: "v1.0.0".to_string(),
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
            charon_version: "v1.7.1".to_string(),
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
            charon_version: "v1.7.1".to_string(),
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
            charon_version: "v1.5.0".to_string(),
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
            charon_version: "v1.6.0".to_string(),
            lock_hash: vec![0xca, 0xfe, 0xba, 0xbe].into(),
            sent_at: None,
            git_hash: String::new(),
            started_at: None,
            builder_api_enabled: false,
            nickname: String::new(),
        }
    }

    #[test]
    fn test_decode_minimal() {
        let decoded = PeerInfo::decode(PEERINFO_MINIMAL).unwrap();
        let expected = make_minimal_peerinfo();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_with_git_hash() {
        let decoded = PeerInfo::decode(PEERINFO_WITH_GIT_HASH).unwrap();
        let expected = make_with_git_hash_peerinfo();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_full() {
        let decoded = PeerInfo::decode(PEERINFO_FULL).unwrap();
        let expected = make_full_peerinfo();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_builder_disabled() {
        let decoded = PeerInfo::decode(PEERINFO_BUILDER_DISABLED).unwrap();
        let expected = make_builder_disabled_peerinfo();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_empty_optional_fields() {
        let decoded = PeerInfo::decode(PEERINFO_EMPTY_OPTIONAL_FIELDS).unwrap();
        let expected = make_empty_optional_peerinfo();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_encode_minimal() {
        let msg = make_minimal_peerinfo();
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf, PEERINFO_MINIMAL);
    }

    #[test]
    fn test_encode_with_git_hash() {
        let msg = make_with_git_hash_peerinfo();
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf, PEERINFO_WITH_GIT_HASH);
    }

    #[test]
    fn test_encode_full() {
        let msg = make_full_peerinfo();
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf, PEERINFO_FULL);
    }

    #[test]
    fn test_encode_builder_disabled() {
        let msg = make_builder_disabled_peerinfo();
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf, PEERINFO_BUILDER_DISABLED);
    }

    #[test]
    fn test_encode_empty_optional_fields() {
        let msg = make_empty_optional_peerinfo();
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf, PEERINFO_EMPTY_OPTIONAL_FIELDS);
    }

    #[test]
    fn test_roundtrip_all_variants() {
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
    async fn test_write_read_protobuf_minimal() {
        let original = make_minimal_peerinfo();

        // Write to a cursor
        let mut buf = Vec::new();
        write_protobuf(&mut buf, &original).await.unwrap();

        // The wire format should be: [varint length][protobuf bytes]
        // Minimal message is 14 bytes, so length prefix is just 1 byte (14 < 128)
        assert_eq!(buf[0] as usize, PEERINFO_MINIMAL.len());
        assert_eq!(&buf[1..], PEERINFO_MINIMAL);

        // Read it back
        let mut cursor = futures::io::Cursor::new(&buf[..]);
        let decoded: PeerInfo = read_protobuf(&mut cursor).await.unwrap();
        assert_eq!(original, decoded);
    }

    #[tokio::test]
    async fn test_write_read_protobuf_full() {
        let original = make_full_peerinfo();

        let mut buf = Vec::new();
        write_protobuf(&mut buf, &original).await.unwrap();

        // Read it back
        let mut cursor = futures::io::Cursor::new(&buf[..]);
        let decoded: PeerInfo = read_protobuf(&mut cursor).await.unwrap();
        assert_eq!(original, decoded);
    }

    #[tokio::test]
    async fn test_write_read_protobuf_all_variants() {
        let variants = [
            make_minimal_peerinfo(),
            make_with_git_hash_peerinfo(),
            make_full_peerinfo(),
            make_builder_disabled_peerinfo(),
            make_empty_optional_peerinfo(),
        ];

        for original in variants {
            let mut buf = Vec::new();
            write_protobuf(&mut buf, &original).await.unwrap();

            let mut cursor = futures::io::Cursor::new(&buf[..]);
            let decoded: PeerInfo = read_protobuf(&mut cursor).await.unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[tokio::test]
    async fn test_read_protobuf_message_too_large() {
        // Create a buffer with a length prefix that exceeds MAX_MESSAGE_SIZE
        let mut buf = Vec::new();
        let large_len = MAX_MESSAGE_SIZE + 1;
        let mut len_buf = unsigned_varint::encode::usize_buffer();
        let encoded_len = unsigned_varint::encode::usize(large_len, &mut len_buf);
        buf.extend_from_slice(encoded_len);

        let mut cursor = futures::io::Cursor::new(&buf[..]);
        let result: io::Result<PeerInfo> = read_protobuf(&mut cursor).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("message too large"));
    }

    #[tokio::test]
    async fn test_read_protobuf_invalid_data() {
        // Create a buffer with valid length but invalid protobuf data
        let invalid_data = [0x05, 0xff, 0xff, 0xff, 0xff, 0xff]; // length 5, then garbage

        let mut cursor = futures::io::Cursor::new(&invalid_data[..]);
        let result: io::Result<PeerInfo> = read_protobuf(&mut cursor).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_read_protobuf_truncated_message() {
        // Create a buffer that claims a length but doesn't have enough bytes
        let truncated = [0x10]; // claims 16 bytes but has none

        let mut cursor = futures::io::Cursor::new(&truncated[..]);
        let result: io::Result<PeerInfo> = read_protobuf(&mut cursor).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn test_multiple_messages_in_stream() {
        let msg1 = make_minimal_peerinfo();
        let msg2 = make_full_peerinfo();
        let msg3 = make_with_git_hash_peerinfo();

        // Write multiple messages to the same buffer
        let mut buf = Vec::new();
        write_protobuf(&mut buf, &msg1).await.unwrap();
        write_protobuf(&mut buf, &msg2).await.unwrap();
        write_protobuf(&mut buf, &msg3).await.unwrap();

        // Read them back in order
        let mut cursor = futures::io::Cursor::new(&buf[..]);
        let decoded1: PeerInfo = read_protobuf(&mut cursor).await.unwrap();
        let decoded2: PeerInfo = read_protobuf(&mut cursor).await.unwrap();
        let decoded3: PeerInfo = read_protobuf(&mut cursor).await.unwrap();

        assert_eq!(msg1, decoded1);
        assert_eq!(msg2, decoded2);
        assert_eq!(msg3, decoded3);
    }
}
