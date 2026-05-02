//! Kryptology-compatible DKG for interoperability with Go's Coinbase Kryptology
//! FROST DKG.
//!
//! This module implements the same DKG protocol as
//! `github.com/coinbase/kryptology/pkg/dkg/frost`, which differs from the
//! standard FROST DKG in frost-core in the hash-to-scalar construction,
//! challenge preimage format, proof representation, and round structure.
//!
//! The output types ([`KeyPackage`], [`PublicKeyPackage`]) are standard
//! frost-core types usable with frost-core's signing protocol.

use std::{collections::BTreeMap, fmt};

use blst::*;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

use super::*;

/// Errors from the kryptology-compatible FROST protocol.
#[derive(Debug, thiserror::Error)]
pub enum KryptologyError {
    /// Participant ID is zero or out of range.
    #[error("invalid participant ID {0}")]
    InvalidParticipantId(u32),
    /// Two or more partial signatures share the same identifier.
    #[error("duplicate participant identifier {0}")]
    DuplicateIdentifier(u32),
    /// Fewer partial signatures than the threshold were provided.
    #[error("insufficient signers")]
    InsufficientSigners,
    /// Invalid number of signers.
    #[error("invalid signer count")]
    InvalidSignerCount,
    /// Invalid proof of knowledge from a specific participant.
    #[error("invalid proof from participant {culprit}")]
    InvalidProof {
        /// The 1-indexed ID of the participant whose proof failed.
        culprit: u32,
    },
    /// Invalid Feldman share from a specific participant.
    #[error("invalid share from participant {culprit}")]
    InvalidShare {
        /// The 1-indexed ID of the participant whose share failed.
        culprit: u32,
    },
    /// Wrong number of received packages.
    #[error("incorrect package count")]
    IncorrectPackageCount,
    /// Failed to deserialize a scalar from wire format bytes.
    #[error("invalid scalar encoding")]
    InvalidScalar,
    /// Failed to deserialize a G1 point from wire format bytes.
    #[error("invalid point encoding")]
    InvalidPoint,
    /// Commitment count does not match threshold.
    #[error("invalid commitment count from participant {participant}")]
    InvalidCommitmentCount {
        /// The participant whose commitment count was wrong.
        participant: u32,
    },
    /// An error from frost-core.
    #[error(transparent)]
    FrostCoreError(#[from] FrostCoreError),
}

/// Kryptology Round 1 broadcast data matching Go's `frost.Round1Bcast`.
///
/// Scalars (`wi`, `ci`) are in **big-endian** byte order to match Go's
/// kryptology wire format. Commitments are compressed G1 points (48 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round1Bcast {
    /// Feldman verifier commitments `[A_{i,0}, ..., A_{i,t-1}]`.
    pub commitments: Vec<[u8; 48]>,
    /// Proof-of-knowledge response scalar (big-endian).
    pub wi: [u8; 32],
    /// Proof-of-knowledge challenge scalar (big-endian).
    pub ci: [u8; 32],
}

/// Kryptology Round 2 broadcast data matching Go's `frost.Round2Bcast`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round2Bcast {
    /// The group verification key (compressed G1, 48 bytes).
    pub verification_key: [u8; 48],
    /// This participant's verification share (compressed G1, 48 bytes).
    pub vk_share: [u8; 48],
}

/// A Shamir secret share matching Go's `sharing.ShamirShare`.
///
/// The `value` field is in **big-endian** byte order.
#[derive(Clone, Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ShamirShare {
    /// The share identifier (1-indexed participant ID).
    #[zeroize(skip)]
    pub id: u32,
    /// The share value as big-endian scalar bytes.
    pub value: [u8; 32],
}

/// Secret state held by a participant between round 1 and round 2.
///
/// # Security
///
/// This MUST NOT be sent to other participants.
#[derive(ZeroizeOnDrop)]
pub struct Round1Secret {
    #[zeroize(skip)]
    id: u32,
    #[zeroize(skip)]
    ctx: u8,
    coefficients: Vec<Scalar>,
    #[zeroize(skip)]
    commitment: VerifiableSecretSharingCommitment,
    #[zeroize(skip)]
    threshold: u16,
    #[zeroize(skip)]
    max_signers: u16,
}

impl Round1Secret {
    /// Reconstruct a [`Round1Secret`] from wire-format test fixture data so
    /// that the standard [`round2`] function can be called.
    ///
    /// Testing-only helper: `own_share` is stored as the constant term of a
    /// synthetic zero polynomial so that [`round2`]'s `from_coefficients`
    /// evaluation returns it unchanged.
    #[cfg(test)]
    pub(crate) fn from_raw(
        id: u32,
        ctx: u8,
        threshold: u16,
        max_signers: u16,
        own_share: &[u8; 32],
        commitment_bytes: &[[u8; 48]],
    ) -> Result<Self, KryptologyError> {
        validate_round_parameters(id, threshold, max_signers)?;

        let own_share_scalar = scalar_from_be(own_share)?;
        let commitment = deserialize_commitment(id, threshold, commitment_bytes)?;

        let mut coefficients = vec![Scalar::ZERO; threshold as usize];
        coefficients[0] = own_share_scalar;

        Ok(Self {
            id,
            ctx,
            coefficients,
            commitment,
            threshold,
            max_signers,
        })
    }
}

/// Convert a `Scalar` to big-endian 32 bytes (Go's wire format).
pub fn scalar_to_be(s: &Scalar) -> [u8; 32] {
    let mut bytes = s.to_bytes();
    bytes.reverse();
    bytes
}

/// Convert big-endian 32 bytes to a `Scalar`.
pub fn scalar_from_be(bytes: &[u8; 32]) -> Result<Scalar, KryptologyError> {
    let mut le = *bytes;
    le.reverse();
    Scalar::from_bytes(&le).ok_or(KryptologyError::InvalidScalar)
}

/// RFC 9380 Section 5.3.1 using SHA-256
#[allow(clippy::arithmetic_side_effects)]
fn expand_msg_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    const B_IN_BYTES: usize = 32; // SHA-256 output
    const S_IN_BYTES: usize = 64; // SHA-256 block size

    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    assert!(ell <= 255, "RFC 9380: ell must be at most 255");
    assert!(
        len_in_bytes <= 65535,
        "RFC 9380: len_in_bytes must fit in 2 bytes"
    );
    assert!(dst.len() <= 255, "RFC 9380: DST must be at most 255 bytes");

    let dst_prime_suffix = [u8::try_from(dst.len()).expect("asserted above")];
    let l_i_b_str = u16::try_from(len_in_bytes)
        .expect("asserted above")
        .to_be_bytes();

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0,1) || DST_prime)
    let mut h0 = Sha256::new();
    h0.update([0u8; S_IN_BYTES]);
    h0.update(msg);
    h0.update(l_i_b_str);
    h0.update([0u8]);
    h0.update(dst);
    h0.update(dst_prime_suffix);
    let b_0: [u8; 32] = h0.finalize().into();

    // b_1 = H(b_0 || I2OSP(1,1) || DST_prime)
    let mut h1 = Sha256::new();
    h1.update(b_0);
    h1.update([1u8]);
    h1.update(dst);
    h1.update(dst_prime_suffix);
    let b_1: [u8; 32] = h1.finalize().into();

    let mut out = Vec::with_capacity(ell * B_IN_BYTES);
    out.extend_from_slice(&b_1);

    let mut b_prev = b_1;
    for i in 2..=ell {
        let mut xored = [0u8; 32];
        for j in 0..32 {
            xored[j] = b_0[j] ^ b_prev[j];
        }
        let mut hi = Sha256::new();
        hi.update(xored);
        hi.update([u8::try_from(i).expect("ell <= 255 asserted above")]);
        hi.update(dst);
        hi.update(dst_prime_suffix);
        let b_i: [u8; 32] = hi.finalize().into();
        out.extend_from_slice(&b_i);
        b_prev = b_i;
    }

    out.truncate(len_in_bytes);
    out
}

fn validate_round_parameters(
    id: u32,
    threshold: u16,
    max_signers: u16,
) -> Result<(), KryptologyError> {
    // Kryptology encodes participant identifiers into a single byte.
    if max_signers > u16::from(u8::MAX) {
        return Err(KryptologyError::InvalidSignerCount);
    }

    validate_num_of_signers(threshold, max_signers)?;

    if id == 0 || id > u32::from(max_signers) {
        return Err(KryptologyError::InvalidParticipantId(id));
    }

    Ok(())
}

/// Kryptology hash-to-scalar.
///
/// See: https://github.com/coinbase/kryptology/blob/1dcc062313d99f2e56ce6abc2003ef63c52dd4a5/pkg/core/curves/bls12381_curve.go#L50
const KRYPTOLOGY_DST: &[u8] = b"BLS12381_XMD:SHA-256_SSWU_RO_";

/// Hash to scalar using kryptology's ExpandMsgXmd construction.
///
/// `ExpandMsgXmd(SHA-256, msg, DST, 48)` -> `Scalar::from_be_bytes_wide`.
fn kryptology_hash_to_scalar(msg: &[u8]) -> Scalar {
    let xmd = expand_msg_xmd(msg, KRYPTOLOGY_DST, 48);
    Scalar::from_be_bytes_wide(&xmd)
}

/// Compute the DKG challenge matching kryptology's format.
///
/// Preimage = `byte(id) || byte(ctx) || A_{i,0}.compressed || R.compressed`
/// (98 bytes).
fn kryptology_challenge(id: u8, ctx: u8, commitment_0: &G1Projective, r: &G1Projective) -> Scalar {
    let mut preimage = Vec::with_capacity(98);
    preimage.push(id);
    preimage.push(ctx);
    preimage.extend_from_slice(&G1Affine::from(commitment_0).to_compressed());
    preimage.extend_from_slice(&G1Affine::from(r).to_compressed());
    kryptology_hash_to_scalar(&preimage)
}

fn deserialize_commitment(
    participant: u32,
    threshold: u16,
    commitments: &[[u8; 48]],
) -> Result<VerifiableSecretSharingCommitment, KryptologyError> {
    if commitments.len() != threshold as usize {
        return Err(KryptologyError::InvalidCommitmentCount { participant });
    }

    VerifiableSecretSharingCommitment::from_commitments(commitments)
        .ok_or(KryptologyError::InvalidPoint)
}

/// Perform Round 1 of the kryptology-compatible DKG.
///
/// Generates the secret polynomial, Feldman commitments, Schnorr
/// proof-of-knowledge, and pre-computes Shamir shares for all other
/// participants.
///
/// # Arguments
/// - `id`: This participant's 1-indexed identifier (1..=max_signers).
/// - `threshold`: Minimum number of signers (t).
/// - `max_signers`: Total number of signers (n).
/// - `ctx`: DKG context byte (typically 0).
/// - `rng`: Cryptographic RNG.
#[allow(clippy::arithmetic_side_effects)]
pub fn round1<R: RngCore + CryptoRng>(
    id: u32,
    threshold: u16,
    max_signers: u16,
    ctx: u8,
    rng: &mut R,
) -> Result<(Round1Bcast, BTreeMap<u32, ShamirShare>, Round1Secret), KryptologyError> {
    validate_round_parameters(id, threshold, max_signers)?;

    // Generate random polynomial coefficients [a_0, ..., a_{t-1}]
    let coefficients: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(&mut *rng)).collect();

    // Feldman commitments: A_{i,k} = a_{i,k} * G
    let commitment_points: Vec<G1Projective> = coefficients
        .iter()
        .map(|c| G1Projective::generator() * *c)
        .collect();

    let commitment = {
        let cc: Vec<CoefficientCommitment> = commitment_points
            .iter()
            .map(|p| CoefficientCommitment::new(*p))
            .collect();
        VerifiableSecretSharingCommitment::new(cc)
    };

    // Schnorr proof of knowledge: sample nonce k, compute R = k*G
    let k = loop {
        let s = Scalar::random(&mut *rng);
        if s != Scalar::ZERO {
            break s;
        }
    };
    let r_point = G1Projective::generator() * k;
    let id_u8 = u8::try_from(id).expect("id <= max_signers <= u8::MAX validated above");
    let ci = kryptology_challenge(id_u8, ctx, &commitment_points[0], &r_point);
    let wi = k + coefficients[0] * ci;

    // Pre-compute Shamir shares for every other participant
    let mut shares = BTreeMap::new();
    for j in 1..=u32::from(max_signers) {
        if j == id {
            continue;
        }
        let j_id = Identifier::from_u32(j)?;
        let share_scalar = SigningShare::from_coefficients(&coefficients, j_id).to_scalar();
        shares.insert(
            j,
            ShamirShare {
                id: j,
                value: scalar_to_be(&share_scalar),
            },
        );
    }

    let bcast = Round1Bcast {
        commitments: commitment_points
            .iter()
            .map(|p| G1Affine::from(p).to_compressed())
            .collect(),
        wi: scalar_to_be(&wi),
        ci: scalar_to_be(&ci),
    };

    let secret = Round1Secret {
        id,
        ctx,
        coefficients,
        commitment,
        threshold,
        max_signers,
    };

    Ok((bcast, shares, secret))
}

/// Perform Round 2 of the kryptology-compatible DKG.
///
/// Verifies all received Round 1 broadcasts (proof-of-knowledge + Feldman
/// verification), aggregates received Shamir shares, and produces the final
/// key material.
///
/// # Arguments
/// - `secret`: The [`Round1Secret`] from this participant's [`round1`] call.
/// - `received_bcasts`: Map from source participant ID to their
///   [`Round1Bcast`].
/// - `received_shares`: Map from source participant ID to the [`ShamirShare`]
///   they sent us.
#[allow(clippy::arithmetic_side_effects)]
pub fn round2(
    secret: Round1Secret,
    received_bcasts: &BTreeMap<u32, Round1Bcast>,
    received_shares: &BTreeMap<u32, ShamirShare>,
) -> Result<(Round2Bcast, KeyPackage, PublicKeyPackage), KryptologyError> {
    let min_received = (secret.threshold - 1) as usize;
    let max_received = (secret.max_signers - 1) as usize;
    if received_bcasts.len() < min_received
        || received_bcasts.len() > max_received
        || received_shares.len() < min_received
        || received_shares.len() > max_received
    {
        return Err(KryptologyError::IncorrectPackageCount);
    }

    let own_identifier = Identifier::from_u32(secret.id)?;
    let own_share_scalar =
        SigningShare::from_coefficients(&secret.coefficients, own_identifier).to_scalar();

    let mut peer_commitments: BTreeMap<Identifier, VerifiableSecretSharingCommitment> =
        BTreeMap::new();
    let mut share_sum = Scalar::ZERO;

    for (&sender_id, bcast) in received_bcasts {
        if sender_id == secret.id {
            return Err(KryptologyError::InvalidParticipantId(sender_id));
        }

        let sender_commitment =
            deserialize_commitment(sender_id, secret.threshold, &bcast.commitments)?;
        let a0 = sender_commitment.coefficients()[0].value();

        // Verify proof of knowledge
        let wi = scalar_from_be(&bcast.wi)?;
        let ci = scalar_from_be(&bcast.ci)?;
        if ci == Scalar::ZERO {
            return Err(KryptologyError::InvalidProof { culprit: sender_id });
        }

        // Reconstruct R' = Wi*G - Ci*A_{j,0}
        let r_reconstructed = G1Projective::generator() * wi - a0 * ci;
        let sender_id_u8 = u8::try_from(sender_id)
            .map_err(|_| KryptologyError::InvalidParticipantId(sender_id))?;
        let ci_check = kryptology_challenge(sender_id_u8, secret.ctx, &a0, &r_reconstructed);
        if !ci_check.constant_time_eq(&ci) {
            return Err(KryptologyError::InvalidProof { culprit: sender_id });
        }

        // Verify Feldman share
        let share = received_shares
            .get(&sender_id)
            .ok_or(KryptologyError::InvalidShare { culprit: sender_id })?;
        if share.id != secret.id {
            return Err(KryptologyError::InvalidShare { culprit: sender_id });
        }
        let share_scalar = scalar_from_be(&share.value)?;

        let signing_share = SigningShare::new(share_scalar);
        let secret_share =
            SecretShare::new(own_identifier, signing_share, sender_commitment.clone());
        secret_share
            .verify()
            .map_err(|_| KryptologyError::InvalidShare { culprit: sender_id })?;

        share_sum = share_sum + share_scalar;

        let sender_identifier = Identifier::from_u32(sender_id)?;
        peer_commitments.insert(sender_identifier, sender_commitment);
    }

    let total_scalar = own_share_scalar + share_sum;

    let signing_share = SigningShare::new(total_scalar);
    let verifying_share_element = G1Projective::generator() * total_scalar;
    let verifying_share = VerifyingShare::new(verifying_share_element);

    // Build PublicKeyPackage from all participants' commitments
    peer_commitments.insert(own_identifier, secret.commitment.clone());
    let commitment_refs: BTreeMap<Identifier, &VerifiableSecretSharingCommitment> =
        peer_commitments.iter().map(|(id, c)| (*id, c)).collect();
    let public_key_package = PublicKeyPackage::from_dkg_commitments(&commitment_refs)?;

    let verifying_key = *public_key_package.verifying_key();

    let key_package = KeyPackage::new(
        own_identifier,
        signing_share,
        verifying_share,
        verifying_key,
        secret.threshold,
    );

    // Serialize Round2Bcast
    let vk_element = verifying_key.to_element();
    let bcast = Round2Bcast {
        verification_key: G1Affine::from(vk_element).to_compressed(),
        vk_share: G1Affine::from(verifying_share_element).to_compressed(),
    };

    Ok((bcast, key_package, public_key_package))
}

/// Domain separation tag for Ethereum 2.0 BLS signatures (proof of possession
/// scheme).
///
/// Matches Go's `bls.NewSigEth2()` which uses `blsSignaturePopDst`.
pub const BLS_SIG_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A BLS partial signature in G2, produced by a single signer's key share.
#[derive(Clone)]
pub struct BlsPartialSignature {
    /// The signer's 1-indexed identifier (used as the Lagrange x-coordinate).
    pub identifier: u32,
    point: blst_p2,
}

impl fmt::Debug for BlsPartialSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut affine = blst_p2_affine::default();
        let mut bytes = [0u8; 96];
        unsafe {
            blst_p2_to_affine(&mut affine, &self.point);
            blst_p2_affine_compress(bytes.as_mut_ptr(), &affine);
        }

        f.debug_struct("BlsPartialSignature")
            .field("identifier", &self.identifier)
            .field("point", &bytes)
            .finish()
    }
}

impl BlsPartialSignature {
    /// Produce a BLS partial signature from a [`KeyPackage`] produced by
    /// kryptology DKG.
    ///
    /// Computes `partial_sig = (key_package.signing_share) * H(msg)` where H
    /// hashes the message to a G2 point using the Ethereum 2.0 DST.
    pub fn from_key_package(key_package: &KeyPackage, msg: &[u8]) -> BlsPartialSignature {
        let scalar = key_package.signing_share().to_scalar();
        let h_msg = hash_to_g2(msg);
        BlsPartialSignature {
            identifier: key_package.identifier().to_u32(),
            point: p2_mult(&h_msg, &scalar),
        }
    }
}

/// A complete BLS signature in G2 (96 bytes compressed).
#[derive(Clone)]
pub struct BlsSignature {
    point: blst_p2,
}

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BlsSignature")
            .field(&self.to_bytes())
            .finish()
    }
}

impl BlsSignature {
    /// Serialize to 96-byte compressed G2 point.
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut affine = blst_p2_affine::default();
        let mut out = [0u8; 96];
        unsafe {
            blst_p2_to_affine(&mut affine, &self.point);
            blst_p2_affine_compress(out.as_mut_ptr(), &affine);
        }
        out
    }

    /// Combine BLS partial signatures via Lagrange interpolation at x = 0.
    ///
    /// Matches Go's `combineSigs` in
    /// `kryptology/pkg/signatures/bls/bls_sig/usual_bls_sig.go`.
    ///
    /// Returns [`KryptologyError::InsufficientSigners`] if `min_signers < 2` or
    /// fewer than `min_signers` partial signatures are provided.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn from_partial_signatures(
        min_signers: u16,
        partial_sigs: &[BlsPartialSignature],
    ) -> Result<Self, KryptologyError> {
        if min_signers < 2 || partial_sigs.len() < min_signers as usize {
            return Err(KryptologyError::InsufficientSigners);
        }

        // Check for duplicate identifiers
        let mut seen = std::collections::BTreeSet::new();
        for ps in partial_sigs {
            if !seen.insert(ps.identifier) {
                return Err(KryptologyError::DuplicateIdentifier(ps.identifier));
            }
        }

        let x_vals: Vec<Scalar> = partial_sigs
            .iter()
            .map(|ps| Scalar::from(u64::from(ps.identifier)))
            .collect();

        let mut combined = blst_p2::default();

        for (i, ps) in partial_sigs.iter().enumerate() {
            // Lagrange coefficient: L_i(0) = prod_{j!=i} ( x_j / (x_j - x_i) )
            let mut lambda = Scalar::ONE;
            for (j, _) in partial_sigs.iter().enumerate() {
                if i == j {
                    continue;
                }
                let num = x_vals[j];
                let den = x_vals[j] - x_vals[i];
                // Duplicate identifiers are rejected above, so this should
                // only fail if the invariant is broken.
                let den_inv = den.invert().ok_or(KryptologyError::InvalidSignerCount)?;
                lambda = lambda * num * den_inv;
            }

            let weighted = p2_mult(&ps.point, &lambda);

            let mut tmp = blst_p2::default();
            unsafe { blst_p2_add_or_double(&mut tmp, &combined, &weighted) };
            combined = tmp;
        }

        Ok(BlsSignature { point: combined })
    }

    /// Verify a BLS signature against a public key.
    ///
    /// Uses the Ethereum 2.0 BLS verification (pairing check) with the
    /// standard DST.
    pub fn verify(&self, verifying_key: &VerifyingKey, msg: &[u8]) -> bool {
        let pk_affine = G1Affine::from(verifying_key.to_element());
        let pk = blst::min_pk::PublicKey::from(pk_affine.0);

        let mut sig_affine = blst_p2_affine::default();
        unsafe { blst_p2_to_affine(&mut sig_affine, &self.point) };
        let sig = blst::min_pk::Signature::from(sig_affine);

        sig.verify(true, msg, BLS_SIG_DST, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
    }
}

/// Hash a message to a G2 point using the Ethereum 2.0 BLS DST.
fn hash_to_g2(msg: &[u8]) -> blst_p2 {
    let mut out = blst_p2::default();
    unsafe {
        blst_hash_to_g2(
            &mut out,
            msg.as_ptr(),
            msg.len(),
            BLS_SIG_DST.as_ptr(),
            BLS_SIG_DST.len(),
            core::ptr::null(),
            0,
        );
    }
    out
}

/// Multiply a G2 point by a scalar.
fn p2_mult(point: &blst_p2, scalar: &Scalar) -> blst_p2 {
    let mut s = blst_scalar::default();
    let mut out = blst_p2::default();
    unsafe {
        blst_scalar_from_fr(&mut s, &scalar.0);
        // BLS12-381 scalar field order has 255 significant bits.
        blst_p2_mult(&mut out, point, s.b.as_ptr(), 255);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    #[test]
    fn scalar_from_be_rejects_invalid_scalar_encoding() {
        assert!(matches!(
            scalar_from_be(&[0xff; 32]),
            Err(KryptologyError::InvalidScalar)
        ));
    }

    #[test]
    fn deserialize_commitment_rejects_wrong_commitment_count() {
        let commitments = [];

        assert!(matches!(
            deserialize_commitment(2, 1, &commitments),
            Err(KryptologyError::InvalidCommitmentCount { participant: 2 })
        ));
    }

    #[test]
    fn deserialize_commitment_rejects_invalid_point() {
        let commitments = [[0u8; 48]];

        assert!(matches!(
            deserialize_commitment(2, 1, &commitments),
            Err(KryptologyError::InvalidPoint)
        ));
    }

    #[test]
    fn round2_rejects_insufficient_package_count() {
        let mut rng = StdRng::seed_from_u64(11);
        let (_bcast, _shares, secret) = round1(1, 2, 3, 0, &mut rng).unwrap();

        assert!(matches!(
            round2(secret, &BTreeMap::new(), &BTreeMap::new()),
            Err(KryptologyError::IncorrectPackageCount)
        ));
    }

    #[test]
    fn from_partial_signatures_rejects_insufficient_signers() {
        assert!(matches!(
            BlsSignature::from_partial_signatures(2, &[]),
            Err(KryptologyError::InsufficientSigners)
        ));
    }

    /// RFC 9380 Section 5.3.1 test vector for expand_msg_xmd with SHA-256.
    /// DST = "QUUX-V01-CS02-with-expander-SHA256-128"
    /// msg = "" (empty), len_in_bytes = 0x20 (32)
    #[test]
    fn expand_msg_xmd_rfc9380_vector() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let msg = b"";
        let expected =
            hex::decode("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")
                .unwrap();

        let result = expand_msg_xmd(msg, dst, 32);
        assert_eq!(result, expected, "expand_msg_xmd empty message vector");
    }

    /// RFC 9380 test vector: msg = "abc", len = 32
    #[test]
    fn expand_msg_xmd_rfc9380_abc() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let msg = b"abc";
        let expected =
            hex::decode("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615")
                .unwrap();

        let result = expand_msg_xmd(msg, dst, 32);
        assert_eq!(result, expected, "expand_msg_xmd abc vector");
    }

    /// RFC 9380 test vector: msg = "", len = 0x80 (128 bytes)
    #[test]
    fn expand_msg_xmd_rfc9380_long_output() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let msg = b"";
        let expected = hex::decode(
            "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e2948\
             5dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60c\
             b02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b2\
             6911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb\
             5ee6b9a7fa5b646c993f0ced",
        )
        .unwrap();

        let result = expand_msg_xmd(msg, dst, 128);
        assert_eq!(result, expected, "expand_msg_xmd 128-byte output vector");
    }

    #[test]
    fn round1_rejects_more_than_255_signers() {
        let mut rng = StdRng::seed_from_u64(42);
        let result = round1(1, 2, 256, 0, &mut rng);

        assert!(matches!(result, Err(KryptologyError::InvalidSignerCount)));
    }

    #[test]
    fn round1_accepts_255_signers_boundary() {
        let mut rng = StdRng::seed_from_u64(4242);
        let (_bcast, shares, _secret) = round1(1, 2, 255, 9, &mut rng)
            .expect("255 signers should remain within kryptology's u8 transport limit");

        assert_eq!(shares.len(), 254);
        assert!(shares.contains_key(&255));
    }

    #[test]
    fn round1_rejects_invalid_signer_counts() {
        let mut rng = StdRng::seed_from_u64(7);

        assert!(matches!(
            round1(1, 1, 3, 0, &mut rng),
            Err(KryptologyError::FrostCoreError(
                FrostCoreError::InvalidMinSigners
            ))
        ));
        assert!(matches!(
            round1(1, 3, 2, 0, &mut rng),
            Err(KryptologyError::FrostCoreError(
                FrostCoreError::InvalidMinSigners
            ))
        ));
        assert!(matches!(
            round1(0, 2, 3, 0, &mut rng),
            Err(KryptologyError::InvalidParticipantId(0))
        ));
    }

    /// Full DKG round-trip: 3-of-3 DKG, then BLS threshold sign and verify.
    #[test]
    fn bls_round_trip_3_of_3() {
        let mut rng = StdRng::seed_from_u64(42);
        let threshold = 3u16;
        let max_signers = 3u16;
        let ctx = 0u8;

        let mut bcasts: BTreeMap<u32, Round1Bcast> = BTreeMap::new();
        let mut all_shares: BTreeMap<u32, BTreeMap<u32, ShamirShare>> = BTreeMap::new();
        let mut secrets: BTreeMap<u32, Round1Secret> = BTreeMap::new();

        for id in 1..=u32::from(max_signers) {
            let (bcast, shares, secret) =
                round1(id, threshold, max_signers, ctx, &mut rng).expect("round1 should succeed");
            bcasts.insert(id, bcast);
            secrets.insert(id, secret);

            for (&target_id, share) in &shares {
                all_shares
                    .entry(target_id)
                    .or_default()
                    .insert(id, share.clone());
            }
        }

        let mut key_packages = BTreeMap::new();
        let mut public_key_packages = Vec::new();
        let mut round2_bcasts = BTreeMap::new();

        for id in 1..=u32::from(max_signers) {
            let received_bcasts: BTreeMap<u32, Round1Bcast> = bcasts
                .iter()
                .filter(|(k, _)| **k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();

            let received_shares = all_shares.remove(&id).unwrap();
            let secret = secrets.remove(&id).unwrap();

            let (r2_bcast, key_package, pub_package) =
                round2(secret, &received_bcasts, &received_shares).expect("round2 should succeed");

            round2_bcasts.insert(id, r2_bcast);
            key_packages.insert(id, key_package);
            public_key_packages.push(pub_package);
        }

        let vk = public_key_packages[0].verifying_key();
        for pkg in &public_key_packages[1..] {
            assert_eq!(
                vk,
                pkg.verifying_key(),
                "all participants must agree on the group key"
            );
        }

        let vk_bytes = round2_bcasts[&1].verification_key;
        for (&id, bcast) in &round2_bcasts {
            assert_eq!(
                bcast.verification_key, vk_bytes,
                "participant {id} round2 broadcast has different group key"
            );
        }

        let message = b"test message";

        let partial_sigs: Vec<_> = key_packages
            .keys()
            .map(|&id| BlsPartialSignature::from_key_package(&key_packages[&id], message))
            .collect();

        let signature = BlsSignature::from_partial_signatures(threshold, &partial_sigs)
            .expect("BLS signature combination should succeed");

        assert!(
            signature.verify(vk, message),
            "3-of-3 BLS threshold signature should verify"
        );
    }

    /// 2-of-3 DKG then BLS threshold signing (Ethereum 2.0 compatible).
    #[test]
    fn bls_round_trip_2_of_3() {
        let mut rng = StdRng::seed_from_u64(123);
        let threshold = 2u16;
        let max_signers = 3u16;
        let ctx = 0u8;

        let mut bcasts: BTreeMap<u32, Round1Bcast> = BTreeMap::new();
        let mut all_shares: BTreeMap<u32, BTreeMap<u32, ShamirShare>> = BTreeMap::new();
        let mut secrets: BTreeMap<u32, Round1Secret> = BTreeMap::new();

        for id in 1..=u32::from(max_signers) {
            let (bcast, shares, secret) =
                round1(id, threshold, max_signers, ctx, &mut rng).unwrap();
            bcasts.insert(id, bcast);
            secrets.insert(id, secret);
            for (&target_id, share) in &shares {
                all_shares
                    .entry(target_id)
                    .or_default()
                    .insert(id, share.clone());
            }
        }

        let mut key_packages = BTreeMap::new();
        let mut public_key_packages = Vec::new();

        for id in 1..=u32::from(max_signers) {
            let received_bcasts: BTreeMap<_, _> = bcasts
                .iter()
                .filter(|(k, _)| **k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let received_shares = all_shares.remove(&id).unwrap();
            let secret = secrets.remove(&id).unwrap();

            let (_r2_bcast, key_package, pub_package) =
                round2(secret, &received_bcasts, &received_shares).unwrap();
            key_packages.insert(id, key_package);
            public_key_packages.push(pub_package);
        }

        let message = b"threshold signing";
        let signers: [u32; 2] = [1, 2];

        let partial_sigs: Vec<_> = signers
            .iter()
            .map(|&id| BlsPartialSignature::from_key_package(&key_packages[&id], message))
            .collect();

        let signature = BlsSignature::from_partial_signatures(threshold, &partial_sigs)
            .expect("BLS signature combination should succeed");

        let vk = public_key_packages[0].verifying_key();
        assert!(
            signature.verify(vk, message),
            "BLS threshold signature should verify"
        );
        let signature_bytes = signature.to_bytes();
        let parsed_signature = blst::min_pk::Signature::from_bytes(&signature_bytes)
            .expect("combined signature should serialize to compressed bytes");
        assert_eq!(parsed_signature.to_bytes(), signature_bytes);

        assert!(
            !signature.verify(vk, b"wrong message"),
            "BLS signature should not verify against a different message"
        );
    }

    /// Verify that an invalid proof is caught in round2.
    #[test]
    fn round2_rejects_invalid_proof() {
        let mut rng = StdRng::seed_from_u64(99);
        let threshold = 2u16;
        let max_signers = 3u16;
        let ctx = 0u8;

        let (mut bcast1, shares1, _secret1) =
            round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
        let (_bcast2, _shares2, secret2) =
            round1(2, threshold, max_signers, ctx, &mut rng).unwrap();
        let (bcast3, shares3, _secret3) = round1(3, threshold, max_signers, ctx, &mut rng).unwrap();

        bcast1.ci[31] ^= 0x01;

        let received_bcasts: BTreeMap<u32, Round1Bcast> =
            [(1, bcast1.clone()), (3, bcast3.clone())].into();
        let received_shares: BTreeMap<u32, ShamirShare> =
            [(1, shares1[&2].clone()), (3, shares3[&2].clone())].into();

        let result = round2(secret2, &received_bcasts, &received_shares);
        assert!(result.is_err());
        match result.unwrap_err() {
            KryptologyError::InvalidProof { culprit } => assert_eq!(culprit, 1),
            other => panic!("expected InvalidProof, got {other:?}"),
        }
    }

    #[test]
    fn round2_rejects_zero_challenge() {
        let mut rng = StdRng::seed_from_u64(98);
        let threshold = 2u16;
        let max_signers = 3u16;
        let ctx = 0u8;

        let (mut bcast1, shares1, _secret1) =
            round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
        let (_bcast2, _shares2, secret2) =
            round1(2, threshold, max_signers, ctx, &mut rng).unwrap();

        bcast1.ci = [0; 32];

        let result = round2(
            secret2,
            &[(1, bcast1)].into(),
            &[(1, shares1[&2].clone())].into(),
        );

        assert!(matches!(
            result,
            Err(KryptologyError::InvalidProof { culprit: 1 })
        ));
    }

    /// Verify that a share addressed to the wrong participant is rejected in
    /// round2.
    #[test]
    fn round2_rejects_share_id_mismatch() {
        let mut rng = StdRng::seed_from_u64(42);
        let threshold = 2u16;
        let max_signers = 3u16;
        let ctx = 0u8;

        let (bcast1, shares1, _secret1) = round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
        let (_bcast2, _shares2, secret2) =
            round1(2, threshold, max_signers, ctx, &mut rng).unwrap();
        let (bcast3, shares3, _secret3) = round1(3, threshold, max_signers, ctx, &mut rng).unwrap();

        let received_bcasts: BTreeMap<u32, Round1Bcast> = [(1, bcast1), (3, bcast3)].into();

        let mut wrong_share = shares1[&2].clone();
        wrong_share.id = 3;
        let received_shares: BTreeMap<u32, ShamirShare> =
            [(1, wrong_share), (3, shares3[&2].clone())].into();

        let result = round2(secret2, &received_bcasts, &received_shares);
        assert!(result.is_err());
        match result.unwrap_err() {
            KryptologyError::InvalidShare { culprit } => assert_eq!(culprit, 1),
            other => panic!("expected InvalidShare, got {other:?}"),
        }
    }

    #[test]
    fn round2_accepts_threshold_subset() {
        let mut rng = StdRng::seed_from_u64(321);
        let threshold = 2u16;
        let max_signers = 3u16;
        let ctx = 0u8;

        let (bcast1, shares1, _secret1) = round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
        let (_bcast2, _shares2, secret2) =
            round1(2, threshold, max_signers, ctx, &mut rng).unwrap();
        let (_bcast3, _shares3, _secret3) =
            round1(3, threshold, max_signers, ctx, &mut rng).unwrap();

        let received_bcasts: BTreeMap<u32, Round1Bcast> = [(1, bcast1)].into();
        let received_shares: BTreeMap<u32, ShamirShare> = [(1, shares1[&2].clone())].into();

        round2(secret2, &received_bcasts, &received_shares)
            .expect("threshold-1 peer packages should be enough");
    }

    #[test]
    fn round2_rejects_missing_share_with_culprit() {
        let mut rng = StdRng::seed_from_u64(322);
        let threshold = 2u16;
        let max_signers = 3u16;
        let ctx = 0u8;

        let (bcast1, _shares1, _secret1) =
            round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
        let (_bcast2, _shares2, secret2) =
            round1(2, threshold, max_signers, ctx, &mut rng).unwrap();
        let (bcast3, shares3, _secret3) = round1(3, threshold, max_signers, ctx, &mut rng).unwrap();

        let received_bcasts: BTreeMap<u32, Round1Bcast> = [(1, bcast1), (3, bcast3)].into();
        let received_shares: BTreeMap<u32, ShamirShare> = [(3, shares3[&2].clone())].into();

        let result = round2(secret2, &received_bcasts, &received_shares);
        assert!(matches!(
            result,
            Err(KryptologyError::InvalidShare { culprit: 1 })
        ));
    }

    #[test]
    fn round2_rejects_self_broadcast() {
        let mut rng = StdRng::seed_from_u64(323);
        let threshold = 2u16;
        let max_signers = 3u16;
        let ctx = 0u8;

        let (_bcast1, shares1, _secret1) =
            round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
        let (bcast2, _shares2, secret2) = round1(2, threshold, max_signers, ctx, &mut rng).unwrap();

        let received_bcasts: BTreeMap<u32, Round1Bcast> = [(2, bcast2)].into();
        let received_shares: BTreeMap<u32, ShamirShare> = [(2, shares1[&2].clone())].into();

        let result = round2(secret2, &received_bcasts, &received_shares);
        assert!(matches!(
            result,
            Err(KryptologyError::InvalidParticipantId(2))
        ));
    }

    #[test]
    fn from_partial_signatures_rejects_duplicate_signers() {
        let mut rng = StdRng::seed_from_u64(324);
        let threshold = 2u16;
        let max_signers = 2u16;
        let ctx = 0u8;
        let message = b"duplicate signer";

        let (bcast1, shares1, secret1) = round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
        let (bcast2, shares2, secret2) = round1(2, threshold, max_signers, ctx, &mut rng).unwrap();

        let (_round2_bcast1, key_package1, _public_key_package1) = round2(
            secret1,
            &[(2, bcast2.clone())].into(),
            &[(2, shares2[&1].clone())].into(),
        )
        .unwrap();
        let (_round2_bcast2, _key_package2, _public_key_package2) = round2(
            secret2,
            &[(1, bcast1)].into(),
            &[(1, shares1[&2].clone())].into(),
        )
        .unwrap();

        let partial = BlsPartialSignature::from_key_package(&key_package1, message);
        let result = BlsSignature::from_partial_signatures(threshold, &[partial.clone(), partial]);

        assert!(matches!(
            result,
            Err(KryptologyError::DuplicateIdentifier(1))
        ));
    }
}
