use std::io;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use prost::Message;
use unsigned_varint::aio::read_usize;

/// Writes a protobuf message with unsigned-varint length prefix to the stream.
pub async fn write_protobuf<M: Message, S: AsyncWrite + Unpin>(
    stream: &mut S,
    msg: &M,
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    let mut len_buf = unsigned_varint::encode::usize_buffer();
    let encoded_len = unsigned_varint::encode::usize(buf.len(), &mut len_buf);
    stream.write_all(encoded_len).await?;
    stream.write_all(&buf).await?;
    stream.flush().await
}

/// Reads a protobuf message with unsigned-varint length prefix from the stream.
pub async fn read_protobuf<M: Message + Default, S: AsyncRead + Unpin>(
    stream: &mut S,
    max_message_size: usize,
) -> io::Result<M> {
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

    let mut buf = vec![0u8; msg_len];
    stream.read_exact(&mut buf).await?;

    M::decode(&buf[..]).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
