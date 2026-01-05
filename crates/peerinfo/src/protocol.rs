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
use tracing::warn;
use unsigned_varint::aio::read_usize;

use crate::peerinfopb::v1::peerinfo::PeerInfo;

/// Maximum message size (64KB should be plenty for peer info).
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

const GIT_HASH_REGEX: &str = r"^[0-9a-f]{7}$";

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

fn validate_peer_info(peer_info: &PeerInfo) -> io::Result<()> {
    // Git hash match
    let regex = regex::Regex::new(GIT_HASH_REGEX).unwrap();
    if !regex.is_match(&peer_info.git_hash) {
        warn!("Invalid git hash: {}", peer_info.git_hash);
    }

    let rtt = 10;
    let expected_sent_at = chrono::Utc::now().timestamp().saturating_add(-rtt / 2);
    let actual_sent_at = peer_info.sent_at.unwrap_or_default().seconds;

    let clock_offset = actual_sent_at.saturating_sub(expected_sent_at);

    Ok(())
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

    validate_peer_info(&response)?;

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

    #[test]
    fn test_git_hash_regex_correct() {
        let regex = regex::Regex::new(GIT_HASH_REGEX).unwrap();
        assert!(regex.is_match("abc1234"));
    }
}
