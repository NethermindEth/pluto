//! # tbls
//!
//! tbls is an implementation of tbls.

use std::collections::HashMap;

use rand_core::{CryptoRng, RngCore};

use crate::types::{Error, Index, PrivateKey, PublicKey, Signature};

/// Tbls trait
pub trait Tbls {
    /// Generates a secret key and returns its compressed
    /// serialized representation.
    fn generate_secret_key(&self, rng: impl RngCore + CryptoRng) -> Result<PrivateKey, Error>;

    /// Generates a secret that is not cryptographically
    /// secure using the provided random number generator. This is useful
    /// for testing.
    fn generate_insecure_secret(&self, rng: impl RngCore + CryptoRng) -> Result<PrivateKey, Error>;

    /// Extracts the public key associated with the secret
    /// passed in input, and returns its compressed serialized
    /// representation.
    fn secret_to_public_key(&self, secret_key: &PrivateKey) -> Result<PublicKey, Error>;

    /// Splits a compressed secret into total units of
    /// secret keys, with the given threshold. It returns a map that
    /// associates each private, compressed private key to its ID.
    ///
    /// # Limitations
    ///
    /// Maximum of 255 shares (total <= 255) due to underlying BLS library
    /// constraints.
    fn threshold_split_insecure(
        &self,
        secret_key: &PrivateKey,
        total: Index,
        threshold: Index,
        rng: impl RngCore + CryptoRng,
    ) -> Result<HashMap<Index, PrivateKey>, Error>;

    /// ThresholdSplit splits a compressed secret into total units of secret
    /// keys, with the given threshold. It returns a map that associates
    /// each private, compressed private key to its ID.
    ///
    /// # Limitations
    ///
    /// Maximum of 255 shares (total <= 255) due to underlying BLS library
    /// constraints.
    fn threshold_split(
        &self,
        secret_key: &PrivateKey,
        total: Index,
        threshold: Index,
    ) -> Result<HashMap<Index, PrivateKey>, Error>;

    /// Recovers a secret from a set of shares
    ///
    /// # Limitations
    ///
    /// Share IDs must be < 255 due to underlying BLS library constraints.
    fn recover_secret(&self, shares: &HashMap<Index, PrivateKey>) -> Result<PrivateKey, Error>;

    /// Aggregates a set of signatures into a single signature
    fn aggregate(&self, signatures: &[Signature]) -> Result<Signature, Error>;

    /// Aggregates a set of partial signatures into a single
    /// signature
    ///
    /// # Limitations
    ///
    /// Share IDs must be < 255 due to underlying BLS library constraints.
    fn threshold_aggregate(
        &self,
        partial_signatures_by_idx: &HashMap<Index, Signature>,
    ) -> Result<Signature, Error>;

    /// Verify verifies a signature
    fn verify(
        &self,
        public_key: &PublicKey,
        data: &[u8],
        raw_signature: &Signature,
    ) -> Result<(), Error>;

    /// Signs a message with a private key
    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Signature, Error>;

    /// Verifies an aggregate signature
    fn verify_aggregate(
        &self,
        public_keys: &[PublicKey],
        signature: Signature,
        data: &[u8],
    ) -> Result<(), Error>;
}
