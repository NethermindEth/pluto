//! Wire protocol helpers for partial signature exchange.

use std::io;

use futures::AsyncWriteExt;
use libp2p::swarm::Stream;
use prost::Message;

use pluto_core::{
    corepb::v1::{core as pbcore, parsigex as pbparsigex},
    types::{Duty, ParSignedDataSet},
};
use pluto_p2p::proto;

use super::{Error, Result as ParsigexResult};

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
pub fn encode_message(duty: &Duty, data_set: &ParSignedDataSet) -> ParsigexResult<Vec<u8>> {
    let pb = pbparsigex::ParSigExMsg {
        duty: Some(pbcore::Duty::try_from(duty)?),
        data_set: Some(pbcore::ParSignedDataSet::try_from(data_set)?),
    };

    Ok(encode_protobuf(&pb))
}

/// Decodes a partial signature exchange message.
pub fn decode_message(bytes: &[u8]) -> ParsigexResult<(Duty, ParSignedDataSet)> {
    let pb: pbparsigex::ParSigExMsg = decode_protobuf(bytes)
        .map_err(|_| Error::from(pluto_core::ParSigExCodecError::InvalidMessageFields))?;
    let duty_pb = pb
        .duty
        .ok_or(pluto_core::ParSigExCodecError::InvalidMessageFields)?;
    let data_set_pb = pb
        .data_set
        .ok_or(pluto_core::ParSigExCodecError::InvalidMessageFields)?;
    let duty = Duty::try_from(&duty_pb)?;
    let data_set = ParSignedDataSet::try_from((&duty.duty_type, &data_set_pb))?;
    Ok((duty, data_set))
}

/// Sends one protobuf message on the stream and closes the write side.
pub async fn send_message(stream: &mut Stream, payload: &[u8]) -> io::Result<()> {
    proto::write_length_delimited(stream, payload).await?;
    let _ = stream.close().await;
    Ok(())
}

/// Receives one protobuf payload from the stream and closes the write side.
pub async fn recv_message(stream: &mut Stream) -> io::Result<Vec<u8>> {
    let bytes = proto::read_length_delimited(stream, proto::MAX_MESSAGE_SIZE).await?;
    let _ = stream.close().await;
    Ok(bytes)
}
