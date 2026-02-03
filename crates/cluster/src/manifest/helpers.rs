//! Cluster manifest helper functions for hashing, signing, and conversions.

use crate::{
    definition::ValidatorAddresses,
    distvalidator::DistValidator,
    manifestpb::v1::{Mutation, SignedMutation, Validator},
};

use super::{ManifestError, Result};

/// Hash length in bytes.
pub(crate) const HASH_LEN: usize = 32;

/// Hashes a signed mutation using SHA-256.
pub(crate) fn hash_signed_mutation(_signed: &SignedMutation) -> Result<Vec<u8>> {
    unimplemented!("hash_signed_mutation")
}

/// Hashes a mutation using SHA-256.
pub(crate) fn hash_mutation(_mutation: &Mutation) -> Result<Vec<u8>> {
    unimplemented!("hash_mutation")
}

/// Verifies that the signed mutation has empty signature and signer fields.
pub(crate) fn verify_empty_sig(_signed: &SignedMutation) -> Result<()> {
    unimplemented!("verify_empty_sig")
}

/// Signs a mutation with a secp256k1 private key.
pub fn sign_k1(_mutation: &Mutation, _secret: &k256::ecdsa::SigningKey) -> Result<SignedMutation> {
    unimplemented!("sign_k1")
}

/// Verifies a k1-signed mutation.
pub(crate) fn verify_k1_signed_mutation(_signed: &SignedMutation) -> Result<()> {
    unimplemented!("verify_k1_signed_mutation")
}

/// Converts a legacy cluster validator to a protobuf validator.
pub fn validator_to_proto(
    _val: &DistValidator,
    _addrs: &ValidatorAddresses,
) -> Result<Validator> {
    unimplemented!("validator_to_proto")
}
