use std::collections::BTreeMap;

use rand::{SeedableRng, rngs::StdRng};

use crate::kryptology;

/// RFC 9380 Section 5.3.1 test vector for expand_msg_xmd with SHA-256.
/// DST = "QUUX-V01-CS02-with-expander-SHA256-128"
/// msg = "" (empty), len_in_bytes = 0x20 (32)
#[test]
fn expand_msg_xmd_rfc9380_vector() {
    let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
    let msg = b"";
    let expected =
        hex::decode("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235").unwrap();

    let result = kryptology::expand_msg_xmd(msg, dst, 32);
    assert_eq!(result, expected, "expand_msg_xmd empty message vector");
}

/// RFC 9380 test vector: msg = "abc", len = 32
#[test]
fn expand_msg_xmd_rfc9380_abc() {
    let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
    let msg = b"abc";
    let expected =
        hex::decode("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615").unwrap();

    let result = kryptology::expand_msg_xmd(msg, dst, 32);
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

    let result = kryptology::expand_msg_xmd(msg, dst, 128);
    assert_eq!(result, expected, "expand_msg_xmd 128-byte output vector");
}

#[test]
fn kryptology_rejects_more_than_255_signers() {
    let mut rng = StdRng::seed_from_u64(42);
    let result = kryptology::round1(1, 2, 256, 0, &mut rng);

    assert!(matches!(
        result,
        Err(kryptology::KryptologyError::InvalidSignerCount)
    ));
}

#[test]
fn kryptology_accepts_255_signers_boundary() {
    let mut rng = StdRng::seed_from_u64(4242);
    let (_bcast, shares, _secret) = kryptology::round1(1, 2, 255, 9, &mut rng)
        .expect("255 signers should remain within kryptology's u8 transport limit");

    assert_eq!(shares.len(), 254);
    assert!(shares.contains_key(&255));
}

#[test]
fn kryptology_rejects_invalid_signer_counts() {
    let mut rng = StdRng::seed_from_u64(7);

    assert!(matches!(
        kryptology::round1(1, 1, 3, 0, &mut rng),
        Err(kryptology::KryptologyError::FrostCoreError(
            crate::FrostCoreError::InvalidMinSigners
        ))
    ));
    assert!(matches!(
        kryptology::round1(1, 3, 2, 0, &mut rng),
        Err(kryptology::KryptologyError::FrostCoreError(
            crate::FrostCoreError::InvalidMinSigners
        ))
    ));
    assert!(matches!(
        kryptology::round1(0, 2, 3, 0, &mut rng),
        Err(kryptology::KryptologyError::InvalidParticipantId(0))
    ));
}

/// Full DKG round-trip: 3-of-3 DKG, then BLS threshold sign and verify.
#[test]
fn kryptology_bls_round_trip_3_of_3() {
    let mut rng = StdRng::seed_from_u64(42);
    let threshold = 3u16;
    let max_signers = 3u16;
    let ctx = 0u8;

    let mut bcasts: BTreeMap<u32, kryptology::Round1Bcast> = BTreeMap::new();
    let mut all_shares: BTreeMap<u32, BTreeMap<u32, kryptology::ShamirShare>> = BTreeMap::new();
    let mut secrets: BTreeMap<u32, kryptology::Round1Secret> = BTreeMap::new();

    for id in 1..=u32::from(max_signers) {
        let (bcast, shares, secret) = kryptology::round1(id, threshold, max_signers, ctx, &mut rng)
            .expect("round1 should succeed");
        bcasts.insert(id, bcast);
        secrets.insert(id, secret);

        for (&target_id, share) in &shares {
            all_shares
                .entry(target_id)
                .or_default()
                .insert(id, share.clone());
        }
    }

    // --- Round 2: each participant verifies + aggregates ---
    let mut key_packages = BTreeMap::new();
    let mut public_key_packages = Vec::new();
    let mut round2_bcasts = BTreeMap::new();

    for id in 1..=u32::from(max_signers) {
        // Collect broadcasts from everyone except ourselves
        let received_bcasts: BTreeMap<u32, kryptology::Round1Bcast> = bcasts
            .iter()
            .filter(|(k, _)| **k != id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        let received_shares = all_shares.remove(&id).unwrap();
        let secret = secrets.remove(&id).unwrap();

        let (r2_bcast, key_package, pub_package) =
            kryptology::round2(secret, &received_bcasts, &received_shares)
                .expect("round2 should succeed");

        round2_bcasts.insert(id, r2_bcast);
        key_packages.insert(id, key_package);
        public_key_packages.push(pub_package);
    }

    // All participants should agree on the group verification key
    let vk = public_key_packages[0].verifying_key();
    for pkg in &public_key_packages[1..] {
        assert_eq!(
            vk,
            pkg.verifying_key(),
            "all participants must agree on the group key"
        );
    }

    // All Round2Bcast should carry the same verification_key
    let vk_bytes = round2_bcasts[&1].verification_key;
    for (&id, bcast) in &round2_bcasts {
        assert_eq!(
            bcast.verification_key, vk_bytes,
            "participant {id} round2 broadcast has different group key"
        );
    }

    // BLS sign with all signers (t-of-t)
    let message = b"test message";

    let partial_sigs: Vec<_> = key_packages
        .keys()
        .map(|&id| kryptology::BlsPartialSignature::from_key_package(&key_packages[&id], message))
        .collect();

    let signature = kryptology::BlsSignature::from_partial_signatures(threshold, &partial_sigs)
        .expect("BLS signature combination should succeed");

    assert!(
        signature.verify(vk, message),
        "3-of-3 BLS threshold signature should verify"
    );
}

/// 2-of-3 DKG then BLS threshold signing (Ethereum 2.0 compatible).
#[test]
fn kryptology_bls_round_trip_2_of_3() {
    let mut rng = StdRng::seed_from_u64(123);
    let threshold = 2u16;
    let max_signers = 3u16;
    let ctx = 0u8;

    // Round 1
    let mut bcasts: BTreeMap<u32, kryptology::Round1Bcast> = BTreeMap::new();
    let mut all_shares: BTreeMap<u32, BTreeMap<u32, kryptology::ShamirShare>> = BTreeMap::new();
    let mut secrets: BTreeMap<u32, kryptology::Round1Secret> = BTreeMap::new();

    for id in 1..=u32::from(max_signers) {
        let (bcast, shares, secret) =
            kryptology::round1(id, threshold, max_signers, ctx, &mut rng).unwrap();
        bcasts.insert(id, bcast);
        secrets.insert(id, secret);
        for (&target_id, share) in &shares {
            all_shares
                .entry(target_id)
                .or_default()
                .insert(id, share.clone());
        }
    }

    // Round 2
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
            kryptology::round2(secret, &received_bcasts, &received_shares).unwrap();
        key_packages.insert(id, key_package);
        public_key_packages.push(pub_package);
    }

    // BLS sign with only participants 1 and 2 (threshold = 2)
    let message = b"threshold signing";
    let signers: [u32; 2] = [1, 2];

    let partial_sigs: Vec<_> = signers
        .iter()
        .map(|&id| kryptology::BlsPartialSignature::from_key_package(&key_packages[&id], message))
        .collect();

    let signature = kryptology::BlsSignature::from_partial_signatures(threshold, &partial_sigs)
        .expect("BLS signature combination should succeed");

    let vk = public_key_packages[0].verifying_key();
    assert!(
        signature.verify(vk, message),
        "BLS threshold signature should verify"
    );

    // Verify wrong message fails
    assert!(
        !signature.verify(vk, b"wrong message"),
        "BLS signature should not verify against a different message"
    );
}

/// Verify that an invalid proof is caught in round2.
#[test]
fn kryptology_invalid_proof_rejected() {
    let mut rng = StdRng::seed_from_u64(99);
    let threshold = 2u16;
    let max_signers = 3u16;
    let ctx = 0u8;

    let (mut bcast1, shares1, _secret1) =
        kryptology::round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
    let (_bcast2, _shares2, secret2) =
        kryptology::round1(2, threshold, max_signers, ctx, &mut rng).unwrap();
    let (bcast3, shares3, _secret3) =
        kryptology::round1(3, threshold, max_signers, ctx, &mut rng).unwrap();

    // Corrupt participant 1's proof (flip LSB of ci, keeping it a valid scalar)
    bcast1.ci[31] ^= 0x01;

    // Participant 2 should reject participant 1's proof
    let received_bcasts: BTreeMap<u32, kryptology::Round1Bcast> =
        [(1, bcast1.clone()), (3, bcast3.clone())].into();
    let received_shares: BTreeMap<u32, kryptology::ShamirShare> =
        [(1, shares1[&2].clone()), (3, shares3[&2].clone())].into();

    let result = kryptology::round2(secret2, &received_bcasts, &received_shares);
    assert!(result.is_err());
    match result.unwrap_err() {
        kryptology::KryptologyError::InvalidProof { culprit } => assert_eq!(culprit, 1),
        other => panic!("expected InvalidProof, got {other:?}"),
    }
}

/// Verify that a share addressed to the wrong participant is rejected in
/// round2.
#[test]
fn kryptology_share_id_mismatch_rejected() {
    let mut rng = StdRng::seed_from_u64(42);
    let threshold = 2u16;
    let max_signers = 3u16;
    let ctx = 0u8;

    let (bcast1, shares1, _secret1) =
        kryptology::round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
    let (_bcast2, _shares2, secret2) =
        kryptology::round1(2, threshold, max_signers, ctx, &mut rng).unwrap();
    let (bcast3, shares3, _secret3) =
        kryptology::round1(3, threshold, max_signers, ctx, &mut rng).unwrap();

    let received_bcasts: BTreeMap<u32, kryptology::Round1Bcast> = [(1, bcast1), (3, bcast3)].into();

    let mut wrong_share = shares1[&2].clone();
    wrong_share.id = 3;
    let received_shares: BTreeMap<u32, kryptology::ShamirShare> =
        [(1, wrong_share), (3, shares3[&2].clone())].into();

    let result = kryptology::round2(secret2, &received_bcasts, &received_shares);
    assert!(result.is_err());
    match result.unwrap_err() {
        kryptology::KryptologyError::InvalidShare { culprit } => assert_eq!(culprit, 1),
        other => panic!("expected InvalidShare, got {other:?}"),
    }
}

#[test]
fn kryptology_round2_accepts_threshold_subset() {
    let mut rng = StdRng::seed_from_u64(321);
    let threshold = 2u16;
    let max_signers = 3u16;
    let ctx = 0u8;

    let (bcast1, shares1, _secret1) =
        kryptology::round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
    let (_bcast2, _shares2, secret2) =
        kryptology::round1(2, threshold, max_signers, ctx, &mut rng).unwrap();
    let (_bcast3, _shares3, _secret3) =
        kryptology::round1(3, threshold, max_signers, ctx, &mut rng).unwrap();

    let received_bcasts: BTreeMap<u32, kryptology::Round1Bcast> = [(1, bcast1)].into();
    let received_shares: BTreeMap<u32, kryptology::ShamirShare> = [(1, shares1[&2].clone())].into();

    kryptology::round2(secret2, &received_bcasts, &received_shares)
        .expect("threshold-1 peer packages should be enough");
}

#[test]
fn kryptology_round2_rejects_missing_share_with_culprit() {
    let mut rng = StdRng::seed_from_u64(322);
    let threshold = 2u16;
    let max_signers = 3u16;
    let ctx = 0u8;

    let (bcast1, _shares1, _secret1) =
        kryptology::round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
    let (_bcast2, _shares2, secret2) =
        kryptology::round1(2, threshold, max_signers, ctx, &mut rng).unwrap();
    let (bcast3, shares3, _secret3) =
        kryptology::round1(3, threshold, max_signers, ctx, &mut rng).unwrap();

    let received_bcasts: BTreeMap<u32, kryptology::Round1Bcast> = [(1, bcast1), (3, bcast3)].into();
    let received_shares: BTreeMap<u32, kryptology::ShamirShare> = [(3, shares3[&2].clone())].into();

    let result = kryptology::round2(secret2, &received_bcasts, &received_shares);
    assert!(matches!(
        result,
        Err(kryptology::KryptologyError::InvalidShare { culprit: 1 })
    ));
}

#[test]
fn kryptology_round2_rejects_self_broadcast() {
    let mut rng = StdRng::seed_from_u64(323);
    let threshold = 2u16;
    let max_signers = 3u16;
    let ctx = 0u8;

    let (_bcast1, shares1, _secret1) =
        kryptology::round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
    let (bcast2, _shares2, secret2) =
        kryptology::round1(2, threshold, max_signers, ctx, &mut rng).unwrap();

    let received_bcasts: BTreeMap<u32, kryptology::Round1Bcast> = [(2, bcast2)].into();
    let received_shares: BTreeMap<u32, kryptology::ShamirShare> = [(2, shares1[&2].clone())].into();

    let result = kryptology::round2(secret2, &received_bcasts, &received_shares);
    assert!(matches!(
        result,
        Err(kryptology::KryptologyError::InvalidParticipantId(2))
    ));
}

#[test]
fn kryptology_duplicate_partial_signatures_rejected() {
    let mut rng = StdRng::seed_from_u64(324);
    let threshold = 2u16;
    let max_signers = 2u16;
    let ctx = 0u8;
    let message = b"duplicate signer";

    let (bcast1, shares1, secret1) =
        kryptology::round1(1, threshold, max_signers, ctx, &mut rng).unwrap();
    let (bcast2, shares2, secret2) =
        kryptology::round1(2, threshold, max_signers, ctx, &mut rng).unwrap();

    let (_round2_bcast1, key_package1, _public_key_package1) = kryptology::round2(
        secret1,
        &[(2, bcast2.clone())].into(),
        &[(2, shares2[&1].clone())].into(),
    )
    .unwrap();
    let (_round2_bcast2, _key_package2, _public_key_package2) = kryptology::round2(
        secret2,
        &[(1, bcast1)].into(),
        &[(1, shares1[&2].clone())].into(),
    )
    .unwrap();

    let partial = kryptology::BlsPartialSignature::from_key_package(&key_package1, message);
    let result =
        kryptology::BlsSignature::from_partial_signatures(threshold, &[partial.clone(), partial]);

    assert!(matches!(
        result,
        Err(kryptology::KryptologyError::DuplicateIdentifier(1))
    ));
}
