//! Port of frost-core types and functions, specialized for BLS12-381 G1 curve operations.
//!
//! Contains the key material types (identifiers, shares, packages) and the
//! polynomial evaluation functions needed by the kryptology-compatible DKG.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use super::*;

/// Errors from key operations.
#[derive(Debug)]
pub enum FrostCoreError {
    /// Participant ID is zero.
    InvalidZeroScalar,
    /// Invalid number of minimum signers (must be >= 2 and <= max_signers).
    InvalidMinSigners,
    /// Invalid number of maximum signers (must be >= 2).
    InvalidMaxSigners,
    /// The secret share verification (Feldman VSS) failed.
    InvalidSecretShare,
    /// Commitment count mismatch during aggregation.
    IncorrectNumberOfCommitments,
    /// The commitment has no coefficients.
    IncorrectCommitment,
}

/// A participant identifier wrapping a non-zero scalar.
///
/// Ported from frost-core/src/identifier.rs:26-48
#[derive(Copy, Clone, Debug)]
pub struct Identifier(Scalar);

impl Identifier {
    /// Create a new identifier from a non-zero u32.
    pub fn from_u32(id: u32) -> Result<Self, FrostCoreError> {
        let scalar = Scalar::from(id as u64);
        if scalar == Scalar::ZERO {
            Err(FrostCoreError::InvalidZeroScalar)
        } else {
            Ok(Self(scalar))
        }
    }

    /// Return the underlying scalar.
    pub fn to_scalar(&self) -> Scalar {
        self.0
    }
}

impl PartialEq for Identifier {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Identifier {}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare using serialized bytes in little-endian order.
        // Ported from frost-core/src/identifier.rs:131-146
        let a = self.0.to_bytes();
        let b = other.0.to_bytes();
        // Compare most-significant byte first (reversed from LE storage).
        for i in (0..32).rev() {
            match a[i].cmp(&b[i]) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        Ordering::Equal
    }
}

/// A commitment to a single polynomial coefficient (a group element).
///
/// Ported from frost-core/src/keys.rs:249-274
#[derive(Copy, Clone, Debug)]
pub struct CoefficientCommitment(G1Projective);

impl CoefficientCommitment {
    /// Create a new coefficient commitment.
    pub fn new(value: G1Projective) -> Self {
        Self(value)
    }

    /// Return the underlying group element.
    pub fn value(&self) -> G1Projective {
        self.0
    }
}

/// The commitments to the coefficients of a secret polynomial, used for
/// Feldman verifiable secret sharing.
///
/// Ported from frost-core/src/keys.rs:308-382
#[derive(Clone, Debug)]
pub struct VerifiableSecretSharingCommitment(Vec<CoefficientCommitment>);

impl VerifiableSecretSharingCommitment {
    /// Create from a vector of coefficient commitments.
    pub fn new(coefficients: Vec<CoefficientCommitment>) -> Self {
        Self(coefficients)
    }

    /// Return the coefficient commitments.
    pub fn coefficients(&self) -> &[CoefficientCommitment] {
        &self.0
    }

    /// Derive a VSS commitment from a list of compressed group elements.
    pub fn from_commitments(commitments: &[[u8; 48]]) -> Option<VerifiableSecretSharingCommitment> {
        let cc = commitments
            .iter()
            .map(|bytes| G1Projective::from_compressed(bytes).map(CoefficientCommitment::new))
            .collect::<Option<Vec<_>>>()?;

        Some(VerifiableSecretSharingCommitment::new(cc))
    }
}

/// A secret scalar value representing a signer's share of the group secret.
///
/// Ported from frost-core/src/keys.rs:87-121
#[derive(Copy, Clone, Debug)]
pub struct SigningShare(Scalar);

impl SigningShare {
    /// Create a signing share from a scalar.
    ///
    /// Ported from frost-core/src/keys.rs:96-98
    pub fn new(scalar: Scalar) -> Self {
        Self(scalar)
    }

    /// Return the underlying scalar.
    ///
    /// Ported from frost-core/src/keys.rs:103-105
    pub fn to_scalar(&self) -> Scalar {
        self.0
    }

    /// Evaluate the polynomial defined by `coefficients` at `peer`.
    ///
    /// Ported from frost-core/src/keys.rs:119-121
    pub fn from_coefficients(coefficients: &[Scalar], peer: Identifier) -> Self {
        Self::new(evaluate_polynomial(peer, coefficients))
    }
}
/// A public group element that represents a single signer's public
/// verification share.
///
/// Ported from frost-core/src/keys.rs:163-214
#[derive(Copy, Clone, Debug)]
pub struct VerifyingShare(G1Projective);

impl VerifyingShare {
    /// Create a verifying share from a group element.
    pub fn new(element: G1Projective) -> Self {
        Self(element)
    }

    /// Return the underlying group element.
    pub fn to_element(&self) -> G1Projective {
        self.0
    }

    /// Compute the verifying share for `identifier` from the summed VSS
    /// commitment.
    ///
    /// Ported from frost-core/src/keys.rs:198-214
    pub fn from_commitment(
        identifier: Identifier,
        commitment: &VerifiableSecretSharingCommitment,
    ) -> Self {
        Self::new(evaluate_vss(identifier, commitment))
    }
}

/// The group public key, used to verify threshold signatures.
///
/// Ported from frost-core/src/verifying_key.rs:15-93
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey(G1Projective);

impl VerifyingKey {
    /// Create a verifying key from a group element.
    pub fn new(element: G1Projective) -> Self {
        Self(element)
    }

    /// Return the underlying group element.
    pub fn to_element(&self) -> G1Projective {
        self.0
    }

    /// Derive the verifying key from the first coefficient commitment.
    ///
    /// Ported from frost-core/src/verifying_key.rs:83-93
    pub fn from_commitment(
        commitment: &VerifiableSecretSharingCommitment,
    ) -> Result<Self, FrostCoreError> {
        Ok(Self::new(
            commitment
                .coefficients()
                .first()
                .ok_or(FrostCoreError::IncorrectCommitment)?
                .value(),
        ))
    }
}

/// Secret and public key material generated during DKG.
///
/// Ported from frost-core/src/keys.rs:399-468
pub struct SecretShare {
    identifier: Identifier,
    signing_share: SigningShare,
    commitment: VerifiableSecretSharingCommitment,
}

impl SecretShare {
    /// Create a new secret share.
    ///
    /// Ported from frost-core/src/keys.rs:418-429
    pub fn new(
        identifier: Identifier,
        signing_share: SigningShare,
        commitment: VerifiableSecretSharingCommitment,
    ) -> Self {
        Self {
            identifier,
            signing_share,
            commitment,
        }
    }

    /// Verify the share against the commitment using Feldman VSS.
    ///
    /// Checks that `G * signing_share == evaluate_vss(identifier, commitment)`.
    ///
    /// Ported from frost-core/src/keys.rs:445-468
    pub fn verify(&self) -> Result<(), FrostCoreError> {
        let f_result = G1Projective::generator() * self.signing_share.to_scalar();
        let result = evaluate_vss(self.identifier, &self.commitment);

        if f_result != result {
            return Err(FrostCoreError::InvalidSecretShare);
        }

        Ok(())
    }
}

/// A key package containing all key material for a participant.
///
/// Ported from frost-core/src/keys.rs:627-665
#[derive(Debug)]
pub struct KeyPackage {
    identifier: Identifier,
    signing_share: SigningShare,
    verifying_share: VerifyingShare,
    verifying_key: VerifyingKey,
    min_signers: u16,
}

impl KeyPackage {
    /// Create a new key package.
    ///
    /// Ported from frost-core/src/keys.rs:650-665
    pub fn new(
        identifier: Identifier,
        signing_share: SigningShare,
        verifying_share: VerifyingShare,
        verifying_key: VerifyingKey,
        min_signers: u16,
    ) -> Self {
        Self {
            identifier,
            signing_share,
            verifying_share,
            verifying_key,
            min_signers,
        }
    }

    /// The participant identifier.
    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    /// The signing share (secret).
    pub fn signing_share(&self) -> &SigningShare {
        &self.signing_share
    }

    /// The participant's public verifying share.
    pub fn verifying_share(&self) -> &VerifyingShare {
        &self.verifying_share
    }

    /// The group public key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// The minimum number of signers.
    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }
}

/// Public data containing all signers' verification shares and the group
/// public key.
///
/// Ported from frost-core/src/keys.rs:720-777
#[derive(Debug)]
pub struct PublicKeyPackage {
    verifying_shares: BTreeMap<Identifier, VerifyingShare>,
    verifying_key: VerifyingKey,
}

impl PublicKeyPackage {
    /// Create a new public key package.
    ///
    /// Ported from frost-core/src/keys.rs:736-745
    pub fn new(
        verifying_shares: BTreeMap<Identifier, VerifyingShare>,
        verifying_key: VerifyingKey,
    ) -> Self {
        Self {
            verifying_shares,
            verifying_key,
        }
    }

    /// The group public key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// The verifying shares for all participants.
    pub fn verifying_shares(&self) -> &BTreeMap<Identifier, VerifyingShare> {
        &self.verifying_shares
    }

    /// Derive a public key package from all participants' DKG commitments.
    ///
    /// Ported from frost-core/src/keys.rs:770-777
    pub fn from_dkg_commitments(
        commitments: &BTreeMap<Identifier, &VerifiableSecretSharingCommitment>,
    ) -> Result<Self, FrostCoreError> {
        let identifiers: BTreeSet<_> = commitments.keys().copied().collect();
        let commitments: Vec<_> = commitments.values().copied().collect();
        let group_commitment = sum_commitments(&commitments)?;
        Self::from_commitment(&identifiers, &group_commitment)
    }

    /// Derive verifying shares for each participant from a summed commitment.
    ///
    /// Ported from frost-core/src/keys.rs:751-763
    fn from_commitment(
        identifiers: &BTreeSet<Identifier>,
        commitment: &VerifiableSecretSharingCommitment,
    ) -> Result<Self, FrostCoreError> {
        let verifying_shares: BTreeMap<_, _> = identifiers
            .iter()
            .map(|id| (*id, VerifyingShare::from_commitment(*id, commitment)))
            .collect();
        Ok(Self::new(
            verifying_shares,
            VerifyingKey::from_commitment(commitment)?,
        ))
    }
}

/// Evaluate a polynomial using Horner's method.
///
/// Given coefficients `[a_0, a_1, ..., a_{t-1}]`, computes
/// `a_0 + a_1 * x + a_2 * x^2 + ... + a_{t-1} * x^{t-1}`.
///
/// Ported from frost-core/src/keys.rs:579-595
fn evaluate_polynomial(identifier: Identifier, coefficients: &[Scalar]) -> Scalar {
    let mut value = Scalar::ZERO;
    let x = identifier.to_scalar();

    for coeff in coefficients.iter().skip(1).rev() {
        value = value + *coeff;
        value = value * x;
    }
    value = value
        + *coefficients
            .first()
            .expect("coefficients must have at least one element");
    value
}

/// Evaluate the VSS verification equation at `identifier`.
///
/// Computes `sum_{k=0}^{t-1} commitment[k] * identifier^k`.
///
/// Ported from frost-core/src/keys.rs:602-615
fn evaluate_vss(
    identifier: Identifier,
    commitment: &VerifiableSecretSharingCommitment,
) -> G1Projective {
    let i = identifier.to_scalar();

    let (_, result) = commitment.0.iter().fold(
        (Scalar::ONE, G1Projective::identity()),
        |(i_to_the_k, sum_so_far), comm_k| {
            (i * i_to_the_k, sum_so_far + comm_k.value() * i_to_the_k)
        },
    );
    result
}

/// Sum multiple participants' commitments element-wise.
///
/// Given commitments from n participants each of length t, produces a single
/// commitment of length t where each element is the sum of the corresponding
/// elements across all participants.
///
/// Ported from frost-core/src/keys.rs:38-62
fn sum_commitments(
    commitments: &[&VerifiableSecretSharingCommitment],
) -> Result<VerifiableSecretSharingCommitment, FrostCoreError> {
    let mut group_commitment = vec![
        CoefficientCommitment::new(G1Projective::identity());
        commitments
            .first()
            .ok_or(FrostCoreError::IncorrectNumberOfCommitments)?
            .0
            .len()
    ];
    for commitment in commitments {
        for (i, c) in group_commitment.iter_mut().enumerate() {
            *c = CoefficientCommitment::new(
                c.value()
                    + commitment
                        .0
                        .get(i)
                        .ok_or(FrostCoreError::IncorrectNumberOfCommitments)?
                        .value(),
            );
        }
    }
    Ok(VerifiableSecretSharingCommitment(group_commitment))
}

/// Validate that (min_signers, max_signers) form a valid pair.
///
/// Ported from frost-core/src/keys.rs:798-815
pub fn validate_num_of_signers(min_signers: u16, max_signers: u16) -> Result<(), FrostCoreError> {
    if min_signers < 2 {
        return Err(FrostCoreError::InvalidMinSigners);
    }
    if max_signers < 2 {
        return Err(FrostCoreError::InvalidMaxSigners);
    }
    if min_signers > max_signers {
        return Err(FrostCoreError::InvalidMinSigners);
    }
    Ok(())
}
