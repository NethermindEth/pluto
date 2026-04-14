use std::collections::BTreeMap;

use pluto_frost::kryptology;
use rand::{SeedableRng, rngs::StdRng};

/// FROST DKG + BLS threshold signing (Ethereum 2.0 compatible).
/// This matches Go's signing flow: non-interactive BLS partial signatures
/// combined via Lagrange interpolation, verified with standard BLS pairings.
///
/// See: https://github.com/coinbase/kryptology/blob/1dcc062313d99f2e56ce6abc2003ef63c52dd4a5/test/frost_dkg/bls/main.go#L23
#[test]
fn kryptology_bls_round_trip_2_of_4_ctx_0() {
    let mut rng = StdRng::seed_from_u64(20260410);
    let threshold = 2u16;
    let max_signers = 4u16;
    let ctx = 0u8;

    let mut round1_bcasts = BTreeMap::new();
    let mut round1_shares: BTreeMap<u32, BTreeMap<u32, kryptology::ShamirShare>> = BTreeMap::new();
    let mut round1_secrets = BTreeMap::new();

    for id in 1..=max_signers as u32 {
        let (bcast, shares, secret) = kryptology::round1(id, threshold, max_signers, ctx, &mut rng)
            .expect("round1 should succeed for each participant");

        assert_eq!(shares.len(), (max_signers - 1) as usize);
        for (&recipient_id, share) in &shares {
            assert_eq!(share.id, recipient_id);
        }

        round1_bcasts.insert(id, bcast);
        round1_secrets.insert(id, secret);

        for (&recipient_id, share) in &shares {
            round1_shares
                .entry(recipient_id)
                .or_default()
                .insert(id, share.clone());
        }
    }

    assert_eq!(round1_bcasts.len(), max_signers as usize);
    assert_eq!(round1_shares.len(), max_signers as usize);

    let mut round2_bcasts = BTreeMap::new();
    let mut key_packages = BTreeMap::new();
    let mut public_key_packages = BTreeMap::new();

    for id in 1..=max_signers as u32 {
        let received_bcasts: BTreeMap<u32, kryptology::Round1Bcast> = round1_bcasts
            .iter()
            .filter(|&(sender_id, _)| *sender_id != id)
            .map(|(&sender_id, bcast)| (sender_id, bcast.clone()))
            .collect();
        let received_shares = round1_shares
            .remove(&id)
            .expect("each participant should receive shares from all peers");
        let secret = round1_secrets
            .remove(&id)
            .expect("round1 secret should exist for each participant");

        assert_eq!(received_bcasts.len(), (max_signers - 1) as usize);
        assert_eq!(received_shares.len(), (max_signers - 1) as usize);

        let (round2_bcast, key_package, public_key_package) =
            kryptology::round2(secret, &received_bcasts, &received_shares)
                .expect("round2 should succeed for each participant");

        round2_bcasts.insert(id, round2_bcast);
        key_packages.insert(id, key_package);
        public_key_packages.insert(id, public_key_package);
    }

    let group_key = public_key_packages[&1].verifying_key();
    for (&id, public_key_package) in &public_key_packages {
        assert_eq!(
            public_key_package.verifying_key(),
            group_key,
            "participant {id} derived a different group verification key"
        );
    }

    let verification_key_bytes = round2_bcasts[&1].verification_key;
    for (&id, round2_bcast) in &round2_bcasts {
        assert_eq!(
            round2_bcast.verification_key, verification_key_bytes,
            "participant {id} broadcast a different round2 verification key"
        );
    }

    // BLS threshold signing (matches Go's main.go)
    let message = b"All my bitcoin is stored here";
    let signing_participants = [1u32, 2u32];

    let partial_sigs: Vec<_> = signing_participants
        .iter()
        .map(|&id| {
            kryptology::BlsPartialSignature::from_key_package(id, &key_packages[&id], message)
        })
        .collect();

    assert_eq!(partial_sigs.len(), threshold as usize);

    let signature = kryptology::BlsSignature::from_partial_signatures(threshold, &partial_sigs)
        .expect("BLS signature combination should succeed");

    assert!(
        signature.verify(group_key, message),
        "BLS threshold signature should verify against the group public key"
    );
}
