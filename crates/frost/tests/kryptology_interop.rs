#![allow(missing_docs)]

use std::collections::BTreeMap;

use pluto_frost::kryptology;
use serde::Deserialize;

#[derive(Clone, Deserialize)]
struct FixtureParticipant {
    id: u32,
    #[serde(deserialize_with = "hex_serde::hex_32")]
    own_share: [u8; 32],
    round1_bcast: FixtureRound1Bcast,
    shares_sent: Vec<FixtureShamirShare>,
    expected_round2: ExpectedRound2,
}

#[derive(Clone, Deserialize)]
struct FixtureRound1Bcast {
    #[serde(deserialize_with = "hex_serde::hex_48_vec")]
    commitments: Vec<[u8; 48]>,
    #[serde(deserialize_with = "hex_serde::hex_32")]
    wi: [u8; 32],
    #[serde(deserialize_with = "hex_serde::hex_32")]
    ci: [u8; 32],
}

#[derive(Clone, Deserialize)]
struct FixtureShamirShare {
    to: u32,
    id: u32,
    #[serde(deserialize_with = "hex_serde::hex_32")]
    value: [u8; 32],
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExpectedRound2 {
    Success {
        #[serde(deserialize_with = "hex_serde::hex_48")]
        verification_key: [u8; 48],
        #[serde(deserialize_with = "hex_serde::hex_48")]
        vk_share: [u8; 48],
        #[serde(deserialize_with = "hex_serde::hex_32")]
        signing_share: [u8; 32],
    },
    InvalidShare {
        culprit: u32,
    },
    InvalidProof {
        culprit: u32,
    },
}

#[derive(Deserialize)]
struct FixtureScenario {
    threshold: u16,
    max_signers: u16,
    ctx: u8,
    participants: Vec<FixtureParticipant>,
}

impl From<&FixtureRound1Bcast> for kryptology::Round1Bcast {
    fn from(f: &FixtureRound1Bcast) -> Self {
        Self {
            commitments: f.commitments.clone(),
            wi: f.wi,
            ci: f.ci,
        }
    }
}

#[test]
fn kryptology_fixture_round2_interop_2_of_3_ctx_0() {
    replay_fixture(
        include_str!("./kryptology_fixtures/2-of-3-ctx-0.json"),
        true,
    );
}

#[test]
fn kryptology_fixture_round2_interop_3_of_3_ctx_0() {
    replay_fixture(
        include_str!("./kryptology_fixtures/3-of-3-ctx-0.json"),
        true,
    );
}

#[test]
fn kryptology_fixture_round2_interop_malformed_share_id() {
    replay_fixture(
        include_str!("./kryptology_fixtures/malformed-share-id.json"),
        false,
    );
}

#[test]
fn kryptology_fixture_round2_interop_invalid_proof() {
    replay_fixture(
        include_str!("./kryptology_fixtures/invalid-proof.json"),
        false,
    );
}

fn replay_fixture(json: &str, require_group_signature: bool) {
    let scenario: FixtureScenario = serde_json::from_str(json).expect("invalid fixture JSON");

    let mut key_packages = BTreeMap::new();
    let mut public_key_packages = Vec::new();

    for participant in &scenario.participants {
        let id = participant.id;
        let received_bcasts = scenario
            .participants
            .iter()
            .filter(|&sender| sender.id != id)
            .map(|sender| {
                (
                    sender.id,
                    kryptology::Round1Bcast::from(&sender.round1_bcast),
                )
            })
            .collect();

        let received_shares = scenario
            .participants
            .iter()
            .filter(|&sender| sender.id != id)
            .map(|sender| {
                let s = sender
                    .shares_sent
                    .iter()
                    .find(|s| s.to == id)
                    .expect("share for recipient");
                (
                    sender.id,
                    kryptology::ShamirShare {
                        id: s.id,
                        value: s.value,
                    },
                )
            })
            .collect();

        let secret = kryptology::Round1Secret::from_raw(
            participant.id,
            scenario.ctx,
            scenario.threshold,
            scenario.max_signers,
            &participant.own_share,
            &participant.round1_bcast.commitments,
        )
        .expect("Round1Secret::from_raw should succeed");
        let result = kryptology::round2(secret, &received_bcasts, &received_shares);

        match &participant.expected_round2 {
            ExpectedRound2::Success {
                verification_key,
                vk_share,
                signing_share,
            } => {
                let (round2_bcast, key_package, public_key_package) =
                    result.expect("round2 should succeed");
                assert_eq!(round2_bcast.verification_key, *verification_key);
                assert_eq!(round2_bcast.vk_share, *vk_share);
                assert_eq!(
                    kryptology::scalar_to_be(&key_package.signing_share().to_scalar()),
                    *signing_share,
                );

                key_packages.insert(id, key_package);
                public_key_packages.push(public_key_package);
            }
            ExpectedRound2::InvalidShare { culprit } => {
                let err = result.expect_err("round2 should fail");
                assert!(
                    matches!(err, kryptology::DkgError::InvalidShare { culprit: c } if c == *culprit),
                    "expected InvalidShare(culprit={culprit}), got {err:?}"
                );
            }
            ExpectedRound2::InvalidProof { culprit } => {
                let err = result.expect_err("round2 should fail");
                assert!(
                    matches!(err, kryptology::DkgError::InvalidProof { culprit: c } if c == *culprit),
                    "expected InvalidProof(culprit={culprit}), got {err:?}"
                );
            }
        }
    }

    if !require_group_signature {
        return;
    }

    let vk = public_key_packages[0].verifying_key();
    for package in &public_key_packages[1..] {
        assert_eq!(vk, package.verifying_key());
    }

    let message = b"kryptology fixture signing";

    let partial_sigs: Vec<_> = key_packages
        .iter()
        .map(|(&id, kp)| kryptology::BlsPartialSignature::from_key_package(id, kp, message))
        .collect();

    let signature =
        kryptology::BlsSignature::from_partial_signatures(scenario.threshold, &partial_sigs)
            .expect("BLS signature combination should succeed");

    assert!(
        signature.verify(vk, message),
        "fixture-derived BLS threshold signature should verify"
    );
}

mod hex_serde {
    use serde::Deserialize;

    fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
        hex::decode(s)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| format!("expected {N} bytes"))
    }

    pub fn hex_32<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        decode_hex(<&str>::deserialize(d)?).map_err(serde::de::Error::custom)
    }

    pub fn hex_48<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        decode_hex(<&str>::deserialize(d)?).map_err(serde::de::Error::custom)
    }

    pub fn hex_48_vec<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<[u8; 48]>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| decode_hex(s).map_err(serde::de::Error::custom))
            .collect()
    }
}
