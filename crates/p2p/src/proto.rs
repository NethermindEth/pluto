use std::io;

use futures::prelude::*;
use prost::Message;
use unsigned_varint::aio::read_usize;

/// Default maximum protobuf message size
pub const MAX_MESSAGE_SIZE: usize = 128 << 20;

/// Writes a length-delimited payload to the stream.
///
/// Format: `[unsigned varint length][payload bytes]`
pub async fn write_length_delimited<S: AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
) -> io::Result<()> {
    let mut len_buf = unsigned_varint::encode::usize_buffer();
    let encoded_len = unsigned_varint::encode::usize(payload.len(), &mut len_buf);

    stream.write_all(encoded_len).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Reads a length-delimited payload from the stream, rejecting oversized
/// messages.
pub async fn read_length_delimited<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_message_size: usize,
) -> io::Result<Vec<u8>> {
    let msg_len = read_usize(&mut *stream)
        .await
        .map_err(|error| match error {
            unsigned_varint::io::ReadError::Io(io_error) => io_error,
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        })?;

    if msg_len > max_message_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {msg_len} bytes (max: {max_message_size})"),
        ));
    }

    let mut buf = vec![0_u8; msg_len];
    stream.read_exact(&mut buf).await?;

    Ok(buf)
}

/// Writes a fixed-size length-delimited payload to the stream.
///
/// Format: `[i64 little-endian length][payload bytes]`
pub async fn write_fixed_size_delimited<S: AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
) -> io::Result<()> {
    let len = i64::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "payload length overflow"))?;

    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Reads a fixed-size length-delimited payload from the stream.
pub async fn read_fixed_size_delimited<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<Vec<u8>> {
    read_fixed_size_delimited_with_max(stream, MAX_MESSAGE_SIZE).await
}

/// Reads a fixed-size length-delimited payload from the stream, rejecting
/// oversized messages.
pub async fn read_fixed_size_delimited_with_max<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_message_size: usize,
) -> io::Result<Vec<u8>> {
    let mut len_buf = [0_u8; 8];
    stream.read_exact(&mut len_buf).await?;

    let len = i64::from_le_bytes(len_buf);
    if len < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid data length",
        ));
    }

    let len = usize::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "payload length overflow"))?;
    if len > max_message_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes (max: {max_message_size})"),
        ));
    }

    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload).await?;

    Ok(payload)
}

/// Encodes a protobuf message and writes it with length-delimited framing.
pub async fn write_protobuf<M: Message, S: AsyncWrite + Unpin>(
    stream: &mut S,
    msg: &M,
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    write_length_delimited(stream, &buf).await
}

/// Encodes a protobuf message and writes it with fixed-size framing.
pub async fn write_fixed_size_protobuf<M: Message, S: AsyncWrite + Unpin>(
    stream: &mut S,
    msg: &M,
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    write_fixed_size_delimited(stream, &buf).await
}

/// Reads a protobuf message using an explicit maximum message size.
pub async fn read_protobuf_with_max_size<M: Message + Default, S: AsyncRead + Unpin>(
    stream: &mut S,
    max_message_size: usize,
) -> io::Result<M> {
    let buf = read_length_delimited(stream, max_message_size).await?;
    M::decode(&buf[..]).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Reads a protobuf message using fixed-size framing and an explicit maximum
/// message size.
pub async fn read_fixed_size_protobuf_with_max_size<M: Message + Default, S: AsyncRead + Unpin>(
    stream: &mut S,
    max_message_size: usize,
) -> io::Result<M> {
    let buf = read_fixed_size_delimited_with_max(stream, max_message_size).await?;
    M::decode(&buf[..]).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;

    use super::*;

    #[tokio::test]
    async fn fixed_size_round_trip() {
        let payload = vec![1, 2, 3, 4];
        let mut cursor = Cursor::new(Vec::new());

        write_fixed_size_delimited(&mut cursor, &payload)
            .await
            .expect("write should succeed");
        cursor.set_position(0);

        let decoded = read_fixed_size_delimited(&mut cursor)
            .await
            .expect("read should succeed");

        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn negative_fixed_size_length_fails() {
        let mut cursor = Cursor::new((-1_i64).to_le_bytes().to_vec());

        let error = read_fixed_size_delimited(&mut cursor)
            .await
            .expect_err("negative sizes must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn oversized_fixed_size_length_fails() {
        let too_large = i64::try_from(MAX_MESSAGE_SIZE)
            .expect("max size should fit in i64")
            .checked_add(1)
            .expect("test length should not overflow");
        let mut cursor = Cursor::new(too_large.to_le_bytes().to_vec());

        let error = read_fixed_size_delimited(&mut cursor)
            .await
            .expect_err("oversized payloads must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn oversized_fixed_size_length_respects_explicit_limit() {
        let explicit_limit = 8_usize;
        let too_large = i64::try_from(explicit_limit)
            .expect("limit should fit in i64")
            .checked_add(1)
            .expect("test length should not overflow");
        let mut cursor = Cursor::new(too_large.to_le_bytes().to_vec());

        let error = read_fixed_size_delimited_with_max(&mut cursor, explicit_limit)
            .await
            .expect_err("explicit fixed-size limit must be enforced");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
