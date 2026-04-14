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

use std::collections::BTreeMap;

use blst::*;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use super::*;

/// Errors from the kryptology-compatible DKG.
#[derive(Debug)]
pub enum DkgError {
    /// Participant ID is zero or out of range.
    InvalidParticipantId(u32),
    /// Two or more partial signatures share the same identifier.
    DuplicateIdentifier(u32),
    /// Fewer partial signatures than the threshold were provided.
    InsufficientSigners,
    /// Invalid number of signers.
    InvalidSignerCount,
    /// Invalid proof of knowledge from a specific participant.
    InvalidProof {
        /// The 1-indexed ID of the participant whose proof failed.
        culprit: u32,
    },
    /// Invalid Feldman share from a specific participant.
    InvalidShare {
        /// The 1-indexed ID of the participant whose share failed.
        culprit: u32,
    },
    /// Wrong number of received packages.
    IncorrectPackageCount,
    /// Failed to deserialize a scalar from wire format bytes.
    InvalidScalar,
    /// Failed to deserialize a G1 point from wire format bytes.
    InvalidPoint,
    /// Commitment count does not match threshold.
    InvalidCommitmentCount {
        /// The participant whose commitment count was wrong.
        participant: u32,
    },
    /// An error from frost-core.
    FrostCoreError(FrostCoreError),
}

impl From<FrostCoreError> for DkgError {
    fn from(e: FrostCoreError) -> Self {
        DkgError::FrostCoreError(e)
    }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShamirShare {
    /// The share identifier (1-indexed participant ID).
    pub id: u32,
    /// The share value as big-endian scalar bytes.
    pub value: [u8; 32],
}

/// Secret state held by a participant between round 1 and round 2.
///
/// # Security
///
/// This MUST NOT be sent to other participants.
pub struct Round1Secret {
    id: u32,
    ctx: u8,
    coefficients: Vec<Scalar>,
    commitment: VerifiableSecretSharingCommitment,
    threshold: u16,
    max_signers: u16,
}

impl Round1Secret {
    /// Reconstruct a [`Round1Secret`] from wire-format data (e.g. a test
    /// fixture) so that the standard [`round2`] function can be called.
    ///
    /// `own_share` is the big-endian scalar the participant computed for
    /// itself.  It is stored as the constant term of a zero polynomial so
    /// that [`round2`]'s `from_coefficients` evaluation returns it
    /// unchanged.
    pub fn from_raw(
        id: u32,
        ctx: u8,
        threshold: u16,
        max_signers: u16,
        own_share: &[u8; 32],
        commitment_bytes: &[[u8; 48]],
    ) -> Result<Self, DkgError> {
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
pub fn scalar_from_be(bytes: &[u8; 32]) -> Result<Scalar, DkgError> {
    let mut le = *bytes;
    le.reverse();
    Scalar::from_bytes(&le).ok_or(DkgError::InvalidScalar)
}

/// RFC 9380 Section 5.3.1 using SHA-256
pub fn expand_msg_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    const B_IN_BYTES: usize = 32; // SHA-256 output
    const S_IN_BYTES: usize = 64; // SHA-256 block size

    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    debug_assert!(ell <= 255 && len_in_bytes <= 65535 && dst.len() <= 255);

    let dst_prime_suffix = [dst.len() as u8];
    let l_i_b_str = [(len_in_bytes >> 8) as u8, (len_in_bytes & 0xff) as u8];

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
        hi.update([i as u8]);
        hi.update(dst);
        hi.update(dst_prime_suffix);
        let b_i: [u8; 32] = hi.finalize().into();
        out.extend_from_slice(&b_i);
        b_prev = b_i;
    }

    out.truncate(len_in_bytes);
    out
}

/// Kryptology hash-to-scalar.
///
/// See: https://github.com/coinbase/kryptology/blob/1dcc062313d99f2e56ce6abc2003ef63c52dd4a5/pkg/core/curves/bls12381_curve.go#L50
const KRYPTOLOGY_DST: &[u8] = b"BLS12381_XMD:SHA-256_SSWU_RO_";

/// Hash to scalar using kryptology's ExpandMsgXmd construction.
///
/// `ExpandMsgXmd(SHA-256, msg, DST, 48)` -> reverse bytes -> pad to 64 ->
/// `Scalar::from_bytes_wide`.
fn kryptology_hash_to_scalar(msg: &[u8]) -> Scalar {
    let xmd = expand_msg_xmd(msg, KRYPTOLOGY_DST, 48);
    let mut reversed = [0u8; 48];
    reversed.copy_from_slice(&xmd);
    reversed.reverse();
    let mut wide = [0u8; 64];
    wide[..48].copy_from_slice(&reversed);
    Scalar::from_bytes_wide(&wide)
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
) -> Result<VerifiableSecretSharingCommitment, DkgError> {
    if commitments.len() != threshold as usize {
        return Err(DkgError::InvalidCommitmentCount { participant });
    }

    VerifiableSecretSharingCommitment::from_commitments(commitments).ok_or(DkgError::InvalidPoint)
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
pub fn round1<R: RngCore + CryptoRng>(
    id: u32,
    threshold: u16,
    max_signers: u16,
    ctx: u8,
    rng: &mut R,
) -> Result<(Round1Bcast, BTreeMap<u32, ShamirShare>, Round1Secret), DkgError> {
    // Kryptology encodes participant identifiers into a single byte.
    if max_signers > u8::MAX as u16 {
        return Err(DkgError::InvalidSignerCount);
    }

    validate_num_of_signers(threshold, max_signers)?;

    if id == 0 || id > max_signers as u32 {
        return Err(DkgError::InvalidParticipantId(id));
    }

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
    let ci = kryptology_challenge(id as u8, ctx, &commitment_points[0], &r_point);
    let wi = k + coefficients[0] * ci;

    // Pre-compute Shamir shares for every other participant
    let mut shares = BTreeMap::new();
    for j in 1..=max_signers as u32 {
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
pub fn round2(
    secret: Round1Secret,
    received_bcasts: &BTreeMap<u32, Round1Bcast>,
    received_shares: &BTreeMap<u32, ShamirShare>,
) -> Result<(Round2Bcast, KeyPackage, PublicKeyPackage), DkgError> {
    let expected = (secret.max_signers - 1) as usize;
    if received_bcasts.len() != expected || received_shares.len() != expected {
        return Err(DkgError::IncorrectPackageCount);
    }

    let own_identifier = Identifier::from_u32(secret.id)?;
    let own_share_scalar =
        SigningShare::from_coefficients(&secret.coefficients, own_identifier).to_scalar();

    let mut peer_commitments: BTreeMap<Identifier, VerifiableSecretSharingCommitment> =
        BTreeMap::new();
    let mut share_sum = Scalar::ZERO;

    for (&sender_id, bcast) in received_bcasts {
        let sender_commitment =
            deserialize_commitment(sender_id, secret.threshold, &bcast.commitments)?;
        let a0 = sender_commitment.coefficients()[0].value();

        // Verify proof of knowledge
        let wi = scalar_from_be(&bcast.wi)?;
        let ci = scalar_from_be(&bcast.ci)?;

        // Reconstruct R' = Wi*G - Ci*A_{j,0}
        let r_reconstructed = G1Projective::generator() * wi - a0 * ci;
        let ci_check = kryptology_challenge(sender_id as u8, secret.ctx, &a0, &r_reconstructed);
        if ci_check != ci {
            return Err(DkgError::InvalidProof { culprit: sender_id });
        }

        // Verify Feldman share
        let share = received_shares
            .get(&sender_id)
            .ok_or(DkgError::IncorrectPackageCount)?;
        if share.id != secret.id {
            return Err(DkgError::InvalidShare { culprit: sender_id });
        }
        let share_scalar = scalar_from_be(&share.value)?;

        let signing_share = SigningShare::new(share_scalar);
        let secret_share =
            SecretShare::new(own_identifier, signing_share, sender_commitment.clone());
        secret_share
            .verify()
            .map_err(|_| DkgError::InvalidShare { culprit: sender_id })?;

        share_sum = share_sum + share_scalar;

        let sender_identifier = Identifier::from_u32(sender_id)?;
        peer_commitments.insert(sender_identifier, sender_commitment);
    }

    let total_scalar = own_share_scalar + share_sum;

    let signing_share = SigningShare::new(total_scalar);
    let verifying_share_element = G1Projective::generator() * total_scalar;
    let verifying_share = VerifyingShare::new(verifying_share_element);

    // Build PublicKeyPackage from all participants' commitments
    peer_commitments.insert(own_identifier, secret.commitment);
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

impl BlsPartialSignature {
    /// Produce a BLS partial signature from a [`KeyPackage`] produced by
    /// kryptology DKG.
    ///
    /// Computes `partial_sig = (key_package.signing_share) * H(msg)` where H
    /// hashes the message to a G2 point using the Ethereum 2.0 DST.
    ///
    /// The `id` must be the original 1-indexed kryptology participant ID.
    pub fn from_key_package(id: u32, key_package: &KeyPackage, msg: &[u8]) -> BlsPartialSignature {
        let scalar = key_package.signing_share().to_scalar();
        {
            let signing_share: &Scalar = &scalar;
            let h_msg = hash_to_g2(msg);
            BlsPartialSignature {
                identifier: id,
                point: p2_mult(&h_msg, signing_share),
            }
        }
    }
}

/// A complete BLS signature in G2 (96 bytes compressed).
#[derive(Clone)]
pub struct BlsSignature {
    point: blst_p2,
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
    /// Returns [`DkgError::InsufficientSigners`] if `min_signers < 2` or
    /// fewer than `min_signers` partial signatures are provided.
    pub fn from_partial_signatures(
        min_signers: u16,
        partial_sigs: &[BlsPartialSignature],
    ) -> Result<Self, DkgError> {
        if min_signers < 2 || partial_sigs.len() < min_signers as usize {
            return Err(DkgError::InsufficientSigners);
        }

        // Check for duplicate identifiers
        let mut seen = std::collections::BTreeSet::new();
        for ps in partial_sigs {
            if !seen.insert(ps.identifier) {
                return Err(DkgError::DuplicateIdentifier(ps.identifier));
            }
        }

        let x_vals: Vec<Scalar> = partial_sigs
            .iter()
            .map(|ps| Scalar::from(ps.identifier as u64))
            .collect();

        let mut combined = blst_p2::default();
        let mut first = true;

        for (i, ps) in partial_sigs.iter().enumerate() {
            // Lagrange coefficient: L_i(0) = prod_{j!=i} ( x_j / (x_j - x_i) )
            let mut lambda = Scalar::ONE;
            for (j, _) in partial_sigs.iter().enumerate() {
                if i == j {
                    continue;
                }
                let num = x_vals[j];
                let den = x_vals[j] - x_vals[i];
                let den_inv = den.invert().ok_or(DkgError::InvalidSignerCount)?;
                lambda = lambda * num * den_inv;
            }

            let weighted = p2_mult(&ps.point, &lambda);

            if first {
                combined = weighted;
                first = false;
            } else {
                let mut tmp = blst_p2::default();
                unsafe { blst_p2_add_or_double(&mut tmp, &combined, &weighted) };
                combined = tmp;
            }
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
        blst_p2_mult(&mut out, point, s.b.as_ptr(), 255);
    }
    out
}
