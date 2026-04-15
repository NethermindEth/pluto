//! Protocol helpers for the DKG sync protocol.

use libp2p::identity::{Keypair, PublicKey};
use libp2p::StreamProtocol;
use pluto_core::version::SemVer;

use crate::dkgpb::v1::sync::MsgSync;

use super::error::{Error, Result};

/// The protocol identifier for DKG sync.
pub const PROTOCOL_NAME: libp2p::StreamProtocol = StreamProtocol::new("/charon/dkg/sync/1.0.0/");

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
        return Err(Error::VersionMismatch {
            expected: expected_version.to_string(),
            got: msg.version.clone(),
        });
    }

    if !public_key.verify(def_hash, &msg.hash_signature) {
        return Err(Error::InvalidDefinitionHashSignature);
    }

    Ok(())
}
