//! Cluster manifest helper functions for hashing, signing, and conversions.

use k256::{
    PublicKey, SecretKey,
    sha2::{Digest, Sha256},
};
use prost_types::Timestamp;

use crate::{
    definition::ValidatorAddresses,
    distvalidator::DistValidator,
    manifestpb::v1::{Mutation, SignedMutation, Validator},
};

use super::{ManifestError, Result};

/// Hash length in bytes.
pub(crate) const HASH_LEN: usize = 32;

/// Get the current timestamp.
///
/// This function returns the current time as a protobuf Timestamp.
/// In production, it uses the system time. In tests, use dependency injection
/// to provide a custom time source instead of this function.
pub fn now() -> Timestamp {
    let now = chrono::Utc::now();
    Timestamp {
        seconds: now.timestamp(),
        #[allow(clippy::cast_possible_wrap)]
        nanos: now.timestamp_subsec_nanos() as i32,
    }
}

/// Hashes a signed mutation using SHA-256.
pub(crate) fn hash_signed_mutation(signed: &SignedMutation) -> Result<Vec<u8>> {
    let mutation = signed
        .mutation
        .as_ref()
        .ok_or(ManifestError::InvalidSignedMutation)?;

    let mut hasher = Sha256::new();

    // Field 0: Mutation
    let mutation_hash = hash_mutation(mutation)?;
    hasher.update(&mutation_hash);

    // Field 1: Signer
    hasher.update(&signed.signer);

    // Field 2: Signature
    hasher.update(&signed.signature);

    Ok(hasher.finalize().to_vec())
}

/// Hashes a mutation using SHA-256.
pub(crate) fn hash_mutation(m: &Mutation) -> Result<Vec<u8>> {
    let data = m
        .data
        .as_ref()
        .ok_or_else(|| ManifestError::InvalidMutation("data is nil".to_string()))?;

    let mut hasher = Sha256::new();

    // Field 0: Parent
    hasher.update(&m.parent);

    // Field 1: Type
    hasher.update(m.r#type.as_bytes());

    // Field 2: Data (TypeUrl + Value)
    hasher.update(data.type_url.as_bytes());
    hasher.update(&data.value);

    Ok(hasher.finalize().to_vec())
}

/// Verifies that the signed mutation has empty signature and signer fields.
#[allow(dead_code)]
pub(crate) fn verify_empty_sig(signed: &SignedMutation) -> Result<()> {
    if !signed.signature.is_empty() {
        return Err(ManifestError::NonEmptyField(
            "non-empty signature".to_string(),
        ));
    }

    if !signed.signer.is_empty() {
        return Err(ManifestError::NonEmptyField("non-empty signer".to_string()));
    }

    Ok(())
}

/// Signs a mutation with a secp256k1 private key.
pub fn sign_k1(m: &Mutation, secret: &SecretKey) -> Result<SignedMutation> {
    let hash = hash_mutation(m)?;

    let sig = pluto_k1util::sign(secret, &hash)
        .map_err(|e| ManifestError::Crypto(format!("sign mutation: {}", e)))?;

    let pubkey = secret.public_key();
    let signer = pubkey.to_sec1_bytes().to_vec();

    Ok(SignedMutation {
        mutation: Some(m.clone()),
        signer: signer.into(),
        signature: sig.to_vec().into(),
    })
}

/// Verifies a k1-signed mutation.
#[allow(dead_code)]
pub(crate) fn verify_k1_signed_mutation(signed: &SignedMutation) -> Result<()> {
    let pubkey = PublicKey::from_sec1_bytes(&signed.signer)
        .map_err(|e| ManifestError::K1Key(format!("parse signer pubkey: {}", e)))?;

    let mutation = signed
        .mutation
        .as_ref()
        .ok_or(ManifestError::InvalidSignedMutation)?;

    let hash = hash_mutation(mutation)?;

    let verified = pluto_k1util::verify_65(&pubkey, &hash, &signed.signature)
        .map_err(|e| ManifestError::Crypto(format!("verify signature: {}", e)))?;

    if !verified {
        return Err(ManifestError::InvalidSignature);
    }

    Ok(())
}

/// Converts a legacy cluster validator to a protobuf validator.
pub fn validator_to_proto(val: &DistValidator, addrs: &ValidatorAddresses) -> Result<Validator> {
    let mut reg_json = Vec::new();

    if !val.zero_registration() {
        // Serialize the BuilderRegistration to JSON
        reg_json = serde_json::to_vec(&val.builder_registration).map_err(|e| {
            ManifestError::BuilderRegistration(format!("marshal builder registration: {}", e))
        })?;
    }

    Ok(Validator {
        public_key: val.pub_key.clone().into(),
        pub_shares: val.pub_shares.iter().map(|s| s.clone().into()).collect(),
        fee_recipient_address: addrs.fee_recipient_address.clone(),
        withdrawal_address: addrs.withdrawal_address.clone(),
        builder_registration_json: reg_json.into(),
    })
}
