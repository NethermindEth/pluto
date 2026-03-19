//! Wire protocol helpers for partial signature exchange.

use std::io;

use futures::prelude::*;
use libp2p::swarm::Stream;
use prost::Message;
use unsigned_varint::aio::read_usize;

use crate::{
    corepb::v1::{core as pbcore, parsigex as pbparsigex},
    types::{Duty, ParSignedDataSet},
};

use super::{Error, Result as ParasigexResult};

/// Maximum accepted message size.
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Encodes a protobuf message to bytes.
pub fn encode_protobuf<M: Message>(message: &M) -> Vec<u8> {
    let mut buf = Vec::with_capacity(message.encoded_len());
    message
        .encode(&mut buf)
        .expect("vec-backed protobuf encoding cannot fail");
    buf
}

/// Decodes a protobuf message from bytes.
pub fn decode_protobuf<M: Message + Default>(
    bytes: &[u8],
) -> std::result::Result<M, prost::DecodeError> {
    M::decode(bytes)
}

/// Encodes a partial signature exchange message.
pub fn encode_message(duty: &Duty, data_set: &ParSignedDataSet) -> ParasigexResult<Vec<u8>> {
    let pb = pbparsigex::ParSigExMsg {
        duty: Some(pbcore::Duty::from(duty)),
        data_set: Some(pbcore::ParSignedDataSet::try_from(data_set)?),
    };

    Ok(encode_protobuf(&pb))
}

/// Decodes a partial signature exchange message.
pub fn decode_message(bytes: &[u8]) -> ParasigexResult<(Duty, ParSignedDataSet)> {
    let pb: pbparsigex::ParSigExMsg =
        decode_protobuf(bytes).map_err(|_| Error::InvalidMessageFields)?;
    let duty_pb = pb.duty.ok_or(Error::InvalidMessageFields)?;
    let data_set_pb = pb.data_set.ok_or(Error::InvalidMessageFields)?;
    let duty = Duty::try_from(&duty_pb)?;
    let data_set = ParSignedDataSet::try_from((&duty.duty_type, &data_set_pb))?;
    Ok((duty, data_set))
}

/// Sends one protobuf message on the stream.
pub async fn send_message(stream: &mut Stream, payload: &[u8]) -> io::Result<()> {
    let mut len_buf = unsigned_varint::encode::usize_buffer();
    let encoded_len = unsigned_varint::encode::usize(payload.len(), &mut len_buf);
    stream.write_all(encoded_len).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Receives one protobuf payload from the stream.
pub async fn recv_message(stream: &mut Stream) -> io::Result<Vec<u8>> {
    let length = read_usize(&mut *stream).await.map_err(|err| match err {
        unsigned_varint::io::ReadError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    })?;

    if length > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {length} bytes"),
        ));
    }

    let mut buf = vec![0_u8; length];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}
