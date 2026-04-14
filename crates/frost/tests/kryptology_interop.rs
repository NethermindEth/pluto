use std::collections::BTreeMap;

use pluto_frost::kryptology;
use serde_json::Value;

const FIXTURE_2_OF_3_CTX_0: &str = include_str!("./kryptology_fixtures/2-of-3-ctx-0.json");
const FIXTURE_3_OF_3_CTX_0: &str = include_str!("./kryptology_fixtures/3-of-3-ctx-0.json");
const FIXTURE_MALFORMED_SHARE_ID: &str =
    include_str!("./kryptology_fixtures/malformed-share-id.json");
const FIXTURE_INVALID_PROOF: &str = include_str!("./kryptology_fixtures/invalid-proof.json");

#[derive(Clone)]
struct FixtureParticipant {
    id: u32,
    own_share: [u8; 32],
    round1_bcast: kryptology::Round1Bcast,
    shares_sent: BTreeMap<u32, kryptology::ShamirShare>,
    expected_round2: ExpectedRound2,
}

#[derive(Clone)]
enum ExpectedRound2 {
    Success {
        verification_key: [u8; 48],
        vk_share: [u8; 48],
        signing_share: [u8; 32],
    },
    Error {
        kind: String,
        culprit: u32,
    },
}

struct FixtureScenario {
    threshold: u16,
    max_signers: u16,
    ctx: u8,
    participants: BTreeMap<u32, FixtureParticipant>,
}

#[test]
fn kryptology_fixture_round2_interop_2_of_3_ctx_0() {
    replay_fixture(FIXTURE_2_OF_3_CTX_0, true);
}

#[test]
fn kryptology_fixture_round2_interop_3_of_3_ctx_0() {
    replay_fixture(FIXTURE_3_OF_3_CTX_0, true);
}

#[test]
fn kryptology_fixture_round2_interop_malformed_share_id() {
    replay_fixture(FIXTURE_MALFORMED_SHARE_ID, false);
}

#[test]
fn kryptology_fixture_round2_interop_invalid_proof() {
    replay_fixture(FIXTURE_INVALID_PROOF, false);
}

fn replay_fixture(json: &str, require_group_signature: bool) {
    let scenario = parse_fixture(json);

    let mut key_packages = BTreeMap::new();
    let mut public_key_packages = Vec::new();

    for (&id, participant) in &scenario.participants {
        let received_bcasts = scenario
            .participants
            .iter()
            .filter(|&(&sender_id, _)| sender_id != id)
            .map(|(&sender_id, sender)| (sender_id, sender.round1_bcast.clone()))
            .collect();

        let received_shares = scenario
            .participants
            .iter()
            .filter(|&(&sender_id, _)| sender_id != id)
            .map(|(&sender_id, sender)| (sender_id, sender.shares_sent[&id].clone()))
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
            ExpectedRound2::Error { kind, culprit } => {
                let err = result.expect_err("round2 should fail");
                match (kind.as_str(), err) {
                    ("invalid_share", kryptology::DkgError::InvalidShare { culprit: got }) => {
                        assert_eq!(got, *culprit);
                    }
                    ("invalid_proof", kryptology::DkgError::InvalidProof { culprit: got }) => {
                        assert_eq!(got, *culprit);
                    }
                    (expected, other) => panic!("expected {expected}, got {other:?}"),
                }
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

fn parse_fixture(json: &str) -> FixtureScenario {
    let root: Value = serde_json::from_str(json).expect("fixture JSON should parse");
    let threshold = get_u64(&root, "threshold") as u16;
    let max_signers = get_u64(&root, "max_signers") as u16;
    let ctx = get_u64(&root, "ctx") as u8;

    let participants = get_array(&root, "participants")
        .iter()
        .map(parse_participant)
        .map(|participant| (participant.id, participant))
        .collect();

    FixtureScenario {
        threshold,
        max_signers,
        ctx,
        participants,
    }
}

fn parse_participant(value: &Value) -> FixtureParticipant {
    let id = get_u64(value, "id") as u32;
    let own_share = decode_hex_32(get_str(value, "own_share"));
    let round1_bcast = parse_round1_bcast(get_value(value, "round1_bcast"));

    let shares_sent = get_array(value, "shares_sent")
        .iter()
        .map(|share| {
            let recipient = get_u64(share, "to") as u32;
            let wire = kryptology::ShamirShare {
                id: get_u64(share, "id") as u32,
                value: decode_hex_32(get_str(share, "value")),
            };
            (recipient, wire)
        })
        .collect();

    let expected_round2 = parse_expected_round2(get_value(value, "expected_round2"));

    FixtureParticipant {
        id,
        own_share,
        round1_bcast,
        shares_sent,
        expected_round2,
    }
}

fn parse_round1_bcast(value: &Value) -> kryptology::Round1Bcast {
    let commitments = get_array(value, "commitments")
        .iter()
        .map(|commitment| decode_hex_48(commitment.as_str().expect("hex string")))
        .collect();

    kryptology::Round1Bcast {
        commitments,
        wi: decode_hex_32(get_str(value, "wi")),
        ci: decode_hex_32(get_str(value, "ci")),
    }
}

fn parse_expected_round2(value: &Value) -> ExpectedRound2 {
    let kind = get_str(value, "kind");
    match kind {
        "success" => ExpectedRound2::Success {
            verification_key: decode_hex_48(get_str(value, "verification_key")),
            vk_share: decode_hex_48(get_str(value, "vk_share")),
            signing_share: decode_hex_32(get_str(value, "signing_share")),
        },
        "invalid_share" | "invalid_proof" => ExpectedRound2::Error {
            kind: String::from(kind),
            culprit: get_u64(value, "culprit") as u32,
        },
        other => panic!("unsupported expected_round2 kind: {other}"),
    }
}

fn get_value<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing key: {key}"))
}

fn get_array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    get_value(value, key)
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("{key} should be an array"))
}

fn get_str<'a>(value: &'a Value, key: &str) -> &'a str {
    get_value(value, key)
        .as_str()
        .unwrap_or_else(|| panic!("{key} should be a string"))
}

fn get_u64(value: &Value, key: &str) -> u64 {
    get_value(value, key)
        .as_u64()
        .unwrap_or_else(|| panic!("{key} should be a u64"))
}

fn decode_hex_32(hex_value: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_value).expect("hex should decode");
    bytes.try_into().expect("expected 32-byte value")
}

fn decode_hex_48(hex_value: &str) -> [u8; 48] {
    let bytes = hex::decode(hex_value).expect("hex should decode");
    bytes.try_into().expect("expected 48-byte value")
}
