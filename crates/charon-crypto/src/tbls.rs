//! # tbls
//!
//! tbls is an implementation of tbls.

use std::collections::HashMap;

use blsful::vsss_rs::elliptic_curve::rand_core::{CryptoRng, RngCore};

/// Public key type
pub type PublicKey = [u8; 48];
/// Private key type
pub type PrivateKey = [u8; 32];
/// Signature type
pub type Signature = [u8; 96];

/// todo: Error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid secret key length.
    InvalidSecretKeyLength,
    /// Invalid public key length.
    InvalidPublicKeyLength,
    /// Invalid signature length.
    InvalidSignatureLength,
    /// Failed to generate secret key.
    FailedToGenerateSecretKey,
    /// Failed to deserialize secret key.
    FailedToDeserializeSecretKey,
    /// Failed to deserialize public key.
    FailedToDeserializePublicKey,
    /// Invalid threshold.
    InvalidThreshold,
    /// Failed to deserialize signature key.
    FailedToDeserializeSignatureKey,
    /// Failed to verify signature.
    FailedToVerifySignature,
    /// Failed to generate signature.
    FailedToGenerateSignature,
}

/// Tbls trait
pub trait Tbls {
    /// GenerateSecretKey generates a secret key and returns its compressed
    /// serialized representation.
    fn generate_secret_key(&self, rng: impl RngCore + CryptoRng) -> Result<PrivateKey, Error>;

    /// generateInsecureSecret generates a secret that is not cryptographically
    /// secure using the provided random number generator. This is useful
    /// for testing.
    fn generate_insecure_secret(&self, rng: impl RngCore + CryptoRng) -> Result<PrivateKey, Error>;

    /// SecretToPublicKey extracts the public key associated with the secret
    /// passed in input, and returns its compressed serialized
    /// representation.
    fn secret_to_public_key(&self, secret_key: &PrivateKey) -> Result<PublicKey, Error>;

    /// thresholdSplitInsecure splits a compressed secret into total units of
    /// secret keys, with the given threshold. It returns a map that
    /// associates each private, compressed private key to its ID.
    fn threshold_split_insecure(
        &self,
        secret_key: &PrivateKey,
        total: u64,
        threshold: u64,
        rng: impl RngCore + CryptoRng,
    ) -> Result<HashMap<u64, PrivateKey>, Error>;

    /// ThresholdSplit splits a compressed secret into total units of secret
    /// keys, with the given threshold. It returns a map that associates
    /// each private, compressed private key to its ID.
    fn threshold_split(
        &self,
        secret_key: &PrivateKey,
        total: u64,
        threshold: u64,
    ) -> Result<HashMap<u64, PrivateKey>, Error>;

    /// RecoverSecret recovers a secret from a set of shares
    fn recover_secret(&self, shares: HashMap<u64, PrivateKey>) -> Result<PrivateKey, Error>;

    /// Aggregate aggregates a set of signatures into a single signature
    fn aggregate(&self, signatures: Vec<Signature>) -> Result<Signature, Error>;

    /// ThresholdAggregate aggregates a set of partial signatures into a single
    /// signature
    fn threshold_aggregate(
        &self,
        partial_signatures_by_idx: HashMap<u64, Signature>,
    ) -> Result<Signature, Error>;

    /// Verify verifies a signature
    fn verify(
        &self,
        public_key: &PublicKey,
        data: &[u8],
        raw_signature: &Signature,
    ) -> Result<(), Error>;

    /// Sign signs a message with a private key
    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Signature, Error>;

    /// ThresholdSign signs a message with a set of private keys
    fn verify_aggregate(
        &self,
        public_keys: Vec<PublicKey>,
        signature: Signature,
        data: &[u8],
    ) -> Result<(), Error>;
}
