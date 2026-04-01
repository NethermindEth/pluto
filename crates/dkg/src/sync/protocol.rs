//! Wire protocol helpers for the DKG sync protocol.

use std::io;

use futures::{AsyncRead, AsyncWrite};
use libp2p::{
    Stream,
    identity::{Keypair, PublicKey},
};
use pluto_core::version::SemVer;
use pluto_p2p::proto::{self, InvalidFixedSizeLength};
use prost::Message;

use crate::dkgpb::v1::sync::{MsgSync, MsgSyncResponse};

use super::error::{Error, Result};

/// The protocol identifier for DKG sync.
pub const PROTOCOL_NAME: libp2p::StreamProtocol = StreamProtocol::new("/charon/dkg/sync/1.0.0/");

use libp2p::StreamProtocol;

/// Signs the definition hash using the same libp2p signing path as Go.
pub fn sign_definition_hash(secret: &k256::SecretKey, def_hash: &[u8]) -> Result<Vec<u8>> {
    let mut der = secret
        .to_sec1_der()
        .map_err(|error| Error::KeyConversion(error.to_string()))?;
    let keypair = Keypair::secp256k1_from_der(&mut der)
        .map_err(|error| Error::KeyConversion(error.to_string()))?;
    keypair
        .sign(def_hash)
        .map_err(|error| Error::SignDefinitionHash(error.to_string()))
}

/// Writes a size-prefixed protobuf to the stream.
pub async fn write_sized_protobuf<M, W>(writer: &mut W, msg: &M) -> Result<()>
where
    M: Message,
    W: AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    msg.encode(&mut buf).map_err(Error::encode)?;
    proto::write_fixed_size_delimited(writer, &buf)
        .await
        .map_err(Error::io)
}

/// Reads a size-prefixed protobuf from the stream.
pub async fn read_sized_protobuf<M, R>(reader: &mut R) -> Result<M>
where
    M: Message + Default,
    R: AsyncRead + Unpin,
{
    let buf = proto::read_fixed_size_delimited(reader)
        .await
        .map_err(map_fixed_size_read_error)?;
    M::decode(buf.as_slice()).map_err(Error::decode)
}

/// Reads a sync request from the stream.
pub async fn read_sync_request(stream: &mut Stream) -> Result<MsgSync> {
    read_sized_protobuf(stream).await
}

/// Writes a sync request to the stream.
pub async fn write_sync_request(stream: &mut Stream, message: &MsgSync) -> Result<()> {
    write_sized_protobuf(stream, message).await
}

/// Reads a sync response from the stream.
pub async fn read_sync_response(stream: &mut Stream) -> Result<MsgSyncResponse> {
    read_sized_protobuf(stream).await
}

/// Writes a sync response to the stream.
pub async fn write_sync_response(stream: &mut Stream, message: &MsgSyncResponse) -> Result<()> {
    write_sized_protobuf(stream, message).await
}

/// Validates a sync request for a known peer public key.
pub fn validate_request_with_public_key(
    def_hash: &[u8],
    expected_version: &SemVer,
    public_key: &PublicKey,
    msg: &MsgSync,
) -> Result<()> {
    let msg_version =
        SemVer::parse(&msg.version).map_err(|error| Error::ParsePeerVersion(error.to_string()))?;

    if msg_version != *expected_version {
        return Err(Error::version_mismatch(expected_version, &msg.version));
    }

    if !public_key.verify(def_hash, &msg.hash_signature) {
        return Err(Error::InvalidDefinitionHashSignature);
    }

    Ok(())
}

fn map_fixed_size_read_error(error: io::Error) -> Error {
    if let Some(source) = error.get_ref()
        && let Some(length) = source.downcast_ref::<InvalidFixedSizeLength>()
    {
        return Error::InvalidMessageLength(length.0);
    }

    Error::io(error)
}

#[cfg(test)]
mod tests {
    use futures::{AsyncWriteExt, io::Cursor};

    use super::*;

    #[tokio::test]
    async fn sized_proto_round_trip() {
        let message = MsgSync {
            timestamp: Some(prost_types::Timestamp {
                seconds: 1,
                nanos: 2,
            }),
            hash_signature: vec![1, 2, 3].into(),
            shutdown: true,
            version: "v1.7".to_string(),
            step: 3,
        };
        let mut cursor = Cursor::new(Vec::new());
        write_sized_protobuf(&mut cursor, &message)
            .await
            .expect("writer should succeed");
        cursor.set_position(0);
        let decoded = read_sized_protobuf::<MsgSync, _>(&mut cursor)
            .await
            .expect("decode should succeed");

        assert_eq!(decoded, message);
    }

    #[tokio::test]
    async fn negative_message_length_fails() {
        let mut cursor = Cursor::new(Vec::new());
        cursor
            .write_all(&(-1_i64).to_le_bytes())
            .await
            .expect("writer should succeed");
        cursor.set_position(0);

        let error = read_sized_protobuf::<MsgSync, _>(&mut cursor)
            .await
            .expect_err("negative sizes must fail");
        assert!(matches!(error, Error::InvalidMessageLength(-1)));
    }
}
