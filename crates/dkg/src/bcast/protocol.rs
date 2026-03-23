//! Wire helpers for the DKG reliable-broadcast protocol.

use futures::AsyncWriteExt;
use libp2p::{PeerId, swarm::Stream};
use prost_types::Any;
use sha2::{Digest, Sha256};

use crate::dkgpb::v1::bcast::{BCastMessage, BCastSigRequest, BCastSigResponse};

use super::error::{Error, Result};

/// Maximum message size supported by the wire codec.
pub(super) const MAX_MESSAGE_SIZE: usize = 128 << 20;

/// Hashes an `Any` message using the `sha256(type_url || value)` algorithm.
pub fn hash_any(any: &Any) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(any.type_url.as_bytes());
    hasher.update(&any.value);
    hasher.finalize().to_vec()
}

/// Signs the wrapped message with the provided key.
pub fn sign_any(secret: &k256::SecretKey, any: &Any) -> Result<Vec<u8>> {
    let hash = hash_any(any);
    Ok(pluto_k1util::sign(secret, &hash)?.to_vec())
}

/// Verifies the provided signatures against the configured peer ordering.
pub fn verify_signatures(any: &Any, signatures: &[Vec<u8>], peers: &[PeerId]) -> Result<()> {
    if signatures.len() != peers.len() {
        return Err(Error::InvalidSignatureCount {
            expected: peers.len(),
            actual: signatures.len(),
        });
    }

    let hash = hash_any(any);

    for (peer, signature) in peers.iter().zip(signatures) {
        if signature.len() != pluto_k1util::SIGNATURE_LEN {
            return Err(Error::InvalidSignatureLength {
                actual: signature.len(),
            });
        }

        let public_key = pluto_p2p::peer::peer_id_to_public_key(peer)?;
        if !pluto_k1util::verify_65(&public_key, &hash, signature)? {
            return Err(Error::InvalidSignature { peer: *peer });
        }
    }

    Ok(())
}

/// Sends a signature request and awaits the corresponding response.
pub async fn send_sig_request(mut stream: Stream, request: BCastSigRequest) -> Result<Vec<u8>> {
    pluto_p2p::protobuf::write_protobuf(&mut stream, &request).await?;
    let response: BCastSigResponse =
        pluto_p2p::protobuf::read_protobuf(&mut stream, MAX_MESSAGE_SIZE).await?;
    stream.close().await?;

    Ok(response.signature.to_vec())
}

/// Sends a fully-signed broadcast message and closes the stream.
pub async fn send_bcast_message(mut stream: Stream, message: BCastMessage) -> Result<()> {
    pluto_p2p::protobuf::write_protobuf(&mut stream, &message).await?;
    stream.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use pluto_p2p::peer::peer_id_from_key;
    use pluto_testutil::random::generate_insecure_k1_key;

    use super::*;

    fn timestamp(seconds: i64) -> prost_types::Timestamp {
        prost_types::Timestamp { seconds, nanos: 0 }
    }

    fn timestamp_with_nanos(seconds: i64, nanos: i32) -> prost_types::Timestamp {
        prost_types::Timestamp { seconds, nanos }
    }

    #[test]
    fn hash_any_matches_go_expected_value() {
        let any = prost_types::Any::from_msg(&timestamp_with_nanos(1, 2)).unwrap();

        assert_eq!(
            hex::encode(hash_any(&any)),
            "9944d042aa3ef54ca4a2b95e43d77fc862c75f9c4a7bd52d3cd1b6220c8adb14"
        );
    }

    #[test]
    fn verify_signatures_rejects_invalid_count_length_and_order() {
        let keys = [
            generate_insecure_k1_key(1),
            generate_insecure_k1_key(2),
            generate_insecure_k1_key(3),
        ];
        let peers = keys
            .iter()
            .map(|key| peer_id_from_key(key.public_key()).unwrap())
            .collect::<Vec<_>>();
        let any = prost_types::Any::from_msg(&timestamp(42)).unwrap();
        let signatures = keys
            .iter()
            .map(|key| sign_any(key, &any).unwrap())
            .collect::<Vec<_>>();

        let error = verify_signatures(&any, &signatures[..2], &peers).unwrap_err();
        assert!(matches!(error, Error::InvalidSignatureCount { .. }));

        let mut bad_length = signatures.clone();
        bad_length[0].truncate(64);
        let error = verify_signatures(&any, &bad_length, &peers).unwrap_err();
        assert!(matches!(error, Error::InvalidSignatureLength { .. }));

        let reversed_peers = peers.iter().rev().copied().collect::<Vec<_>>();
        let error = verify_signatures(&any, &signatures, &reversed_peers).unwrap_err();
        assert!(matches!(error, Error::InvalidSignature { .. }));
    }
}
