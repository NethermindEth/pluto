//! # tbls
//!
//! tbls is an implementation of tbls.

use std::collections::HashMap;

use rand::Rng;

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
}

/// Tbls trait
pub trait Tbls {
    /// GenerateSecretKey generates a secret key and returns its compressed
    /// serialized representation.
    fn generate_secret_key(&self) -> Result<PrivateKey, Error>;

    /// generateInsecureSecret generates a secret that is not cryptographically
    /// secure using the provided random number generator. This is useful
    /// for testing.
    fn generate_insecure_secret(&self, _rng: &mut impl Rng) -> Result<PrivateKey, Error>;

    /// SecretToPublicKey extracts the public key associated with the secret
    /// passed in input, and returns its compressed serialized
    /// representation.
    fn secret_to_public_key(&self, _secret_key: &PrivateKey) -> Result<PublicKey, Error>;

    /// thresholdSplitInsecure splits a compressed secret into total units of
    /// secret keys, with the given threshold. It returns a map that
    /// associates each private, compressed private key to its ID.
    fn threshold_split_insecure(
        &self,
        _secret_key: &PrivateKey,
        _total: u64,
        _threshold: u64,
        _rng: &mut impl Rng,
    ) -> Result<HashMap<u64, PrivateKey>, Error>;

    /// ThresholdSplit splits a compressed secret into total units of secret
    /// keys, with the given threshold. It returns a map that associates
    /// each private, compressed private key to its ID.
    fn threshold_split(
        &self,
        _secret_key: &PrivateKey,
        _total: u64,
        _threshold: u64,
    ) -> Result<HashMap<u64, PrivateKey>, Error>;

    /// RecoverSecret recovers a secret from a set of shares
    fn recover_secret(&self, _shares: HashMap<u64, PrivateKey>) -> Result<PrivateKey, Error>;

    /// Aggregate aggregates a set of signatures into a single signature
    fn aggregate(&self, _signatures: Vec<Signature>) -> Result<Signature, Error>;

    /// ThresholdAggregate aggregates a set of partial signatures into a single
    /// signature
    fn threshold_aggregate(
        &self,
        _partial_signatures_by_idx: HashMap<u64, Signature>,
    ) -> Result<Signature, Error>;

    /// Verify verifies a signature
    fn verify(
        &self,
        _public_key: &PublicKey,
        _data: &[u8],
        _raw_signature: &Signature,
    ) -> Result<(), Error>;

    /// Sign signs a message with a private key
    fn sign(&self, _private_key: &PrivateKey, _data: &[u8]) -> Result<Signature, Error>;

    /// ThresholdSign signs a message with a set of private keys
    fn verify_aggregate(
        &self,
        _public_keys: Vec<PublicKey>,
        _signature: Signature,
        _data: &[u8],
    ) -> Result<(), Error>;
}
