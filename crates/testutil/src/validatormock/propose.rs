//! Block proposal + builder registration drivers.
//!
//! Rust port of `charon/testutil/validatormock/propose.go`. Mirrors the Go
//! `ProposeBlock` flow: fetch active validators, locate the slot proposer
//! via the proposer-duties endpoint, build a randao reveal, fetch the block
//! from `produce_block_v3`, sign its tree-hash root with
//! `DomainBeaconProposer`, and POST the signed block (or signed blinded block)
//! back. Also ports `Register` for builder validator registrations using
//! `DomainApplicationBuilder` over epoch 0.

use pluto_eth2api::{
    EthBeaconNodeApiClient, ProduceBlockOpts,
    spec::{
        BuilderVersion, altair, bellatrix, capella, deneb, electra, fulu, phase0,
        phase0::{BLSPubKey, BLSSignature, Root, Slot},
    },
    v1,
    versioned::{
        ProposalBlock, SignedBlindedProposalBlock, SignedProposalBlock,
        VersionedSignedBlindedProposal, VersionedSignedProposal,
        VersionedSignedValidatorRegistration,
    },
};
use pluto_eth2util::{
    helpers::epoch_from_slot,
    signing::{DomainName, get_data_root},
    types::SignedEpoch,
};
use tree_hash::TreeHash;

use super::{
    active_validators,
    error::{Error, Result},
};

/// Builder registration variant the Go code calls `BuilderVersionV1`. Pluto's
/// versioned enum spells the same value `BuilderVersion::V1`.
const BUILDER_VERSION_V1: BuilderVersion = BuilderVersion::V1;

/// Convenience alias matching Go's `*eth2api.VersionedValidatorRegistration`
/// parameter type. Pluto's versioned enum is named for *signed* payloads, so we
/// reuse it and ignore the `signature` field on its inner `v1` payload.
pub type VersionedValidatorRegistration = VersionedSignedValidatorRegistration;

/// Drives a single-slot block proposal end-to-end.
///
/// Mirrors `ProposeBlock` from `charon/testutil/validatormock/propose.go`. The
/// `signer` parameter is the type-erased `SignFunc` from
/// [`super::sign`]; in production it wraps real BLS secrets, in tests a stub
/// that copies the pubkey bytes into the signature suffices.
pub async fn propose_block(
    client: &EthBeaconNodeApiClient,
    signer: &super::SignFunc,
    slot: Slot,
) -> Result<()> {
    // Ensure active validators are queryable. Mirrors Go's
    // `eth2Cl.ActiveValidators` call: surfaces beacon-node errors before duty
    // lookups proceed.
    let _ = active_validators(client).await?;

    let epoch = epoch_from_slot(client, slot).await?;

    let duties = client
        .get_proposer_duties(epoch)
        .await
        .map_err(|err| Error::Malformed(format!("proposer duties: {err:#}")))?
        .data;

    let Some(duty) = duties.iter().find(|d| d.slot == slot) else {
        // Go returns nil when this validator is not the slot proposer.
        return Ok(());
    };
    let pubkey = duty.pubkey;

    // RANDAO reveal: tree-hash the eth2util `SignedEpoch{epoch, zero-sig}` and
    // sign it under `DomainRandao` at the slot's epoch.
    let randao_message_root = SignedEpoch {
        epoch,
        signature: [0u8; 96],
    }
    .tree_hash_root()
    .0;
    let randao_sig_data = get_data_root(client, DomainName::Randao, epoch, randao_message_root)
        .await
        .map_err(Error::from)?;
    let randao = signer.sign(&pubkey, &randao_sig_data)?;

    // Fetch the unsigned proposal from /eth/v3/validator/blocks/{slot}.
    let proposal = client
        .produce_block_v3(&ProduceBlockOpts {
            slot,
            randao_reveal: randao,
            graffiti: None,
            skip_randao_verification: false,
            builder_boost_factor: None,
        })
        .await
        .map_err(|err| Error::Malformed(format!("vmock beacon block proposal: {err:#}")))?;

    let version = proposal.version();
    let signature = sign_with_proposer(signer, &pubkey, client, epoch, proposal.root()).await?;

    match sign_proposal(proposal.block, signature) {
        SignedBlock::Full(block) => client
            .publish_block_v2(
                &VersionedSignedProposal {
                    version,
                    blinded: false,
                    block,
                },
                None,
            )
            .await
            .map_err(|err| Error::Malformed(format!("publish-block-v2: {err:#}"))),
        SignedBlock::Blinded(block) => client
            .publish_blinded_block_v2(&VersionedSignedBlindedProposal { version, block }, None)
            .await
            .map_err(|err| Error::Malformed(format!("publish-blinded-block-v2: {err:#}"))),
    }
}

/// Signs and submits a builder validator registration.
///
/// Mirrors `Register` from `charon/testutil/validatormock/propose.go`. The Go
/// implementation switches on `signedRegistration.Version` before populating
/// it, which always reads the zero value `BuilderVersionV1` and therefore
/// silently behaves as if the input were V1. The Rust port switches on the
/// *input* registration's version (the obviously intended behaviour); when
/// any non-V1 variant lands here we surface [`Error::UnsupportedVariant`]
/// instead of mis-tagging the signed payload.
pub async fn register(
    client: &EthBeaconNodeApiClient,
    signer: &super::SignFunc,
    registration: &VersionedValidatorRegistration,
    pubshare: BLSPubKey,
) -> Result<()> {
    let message_root = registration
        .message_root()
        .ok_or(Error::UnsupportedVariant("registration version"))?;

    // Always use epoch 0 for DomainApplicationBuilder.
    let sig_data = get_data_root(client, DomainName::ApplicationBuilder, 0, message_root).await?;
    let sig = signer.sign(&pubshare, &sig_data)?;

    match registration.version {
        BUILDER_VERSION_V1 => {
            let inner = registration
                .v1
                .as_ref()
                .ok_or(Error::UnsupportedVariant("missing v1 payload"))?;
            let signed = v1::SignedValidatorRegistration {
                message: inner.message.clone(),
                signature: sig,
            };

            client
                .register_validator(&[signed])
                .await
                .map_err(|err| Error::Malformed(format!("register-validator: {err:#}")))
        }
        BuilderVersion::Unknown => Err(Error::UnsupportedVariant("registration version")),
    }
}

/// A signed proposal, routed to the publish endpoint matching its shape.
enum SignedBlock {
    Full(SignedProposalBlock),
    Blinded(SignedBlindedProposalBlock),
}

/// Attaches `signature` to an unsigned proposal block.
fn sign_proposal(block: ProposalBlock, signature: BLSSignature) -> SignedBlock {
    match block {
        ProposalBlock::Phase0(message) => {
            SignedBlock::Full(SignedProposalBlock::Phase0(phase0::SignedBeaconBlock {
                message,
                signature,
            }))
        }
        ProposalBlock::Altair(message) => {
            SignedBlock::Full(SignedProposalBlock::Altair(altair::SignedBeaconBlock {
                message,
                signature,
            }))
        }
        ProposalBlock::Bellatrix(message) => SignedBlock::Full(SignedProposalBlock::Bellatrix(
            bellatrix::SignedBeaconBlock { message, signature },
        )),
        ProposalBlock::Capella(message) => {
            SignedBlock::Full(SignedProposalBlock::Capella(capella::SignedBeaconBlock {
                message,
                signature,
            }))
        }
        ProposalBlock::Deneb {
            block,
            kzg_proofs,
            blobs,
        } => SignedBlock::Full(SignedProposalBlock::Deneb(deneb::SignedBlockContents {
            signed_block: deneb::SignedBeaconBlock {
                message: *block,
                signature,
            },
            kzg_proofs,
            blobs,
        })),
        ProposalBlock::Electra {
            block,
            kzg_proofs,
            blobs,
        } => SignedBlock::Full(SignedProposalBlock::Electra(electra::SignedBlockContents {
            signed_block: electra::SignedBeaconBlock {
                message: *block,
                signature,
            },
            kzg_proofs,
            blobs,
        })),
        ProposalBlock::Fulu {
            block,
            kzg_proofs,
            blobs,
        } => SignedBlock::Full(SignedProposalBlock::Fulu(fulu::SignedBlockContents {
            signed_block: electra::SignedBeaconBlock {
                message: *block,
                signature,
            },
            kzg_proofs,
            blobs,
        })),
        ProposalBlock::BellatrixBlinded(message) => {
            SignedBlock::Blinded(SignedBlindedProposalBlock::Bellatrix(
                bellatrix::SignedBlindedBeaconBlock { message, signature },
            ))
        }
        ProposalBlock::CapellaBlinded(message) => {
            SignedBlock::Blinded(SignedBlindedProposalBlock::Capella(
                capella::SignedBlindedBeaconBlock { message, signature },
            ))
        }
        ProposalBlock::DenebBlinded(message) => {
            SignedBlock::Blinded(SignedBlindedProposalBlock::Deneb(
                deneb::SignedBlindedBeaconBlock { message, signature },
            ))
        }
        ProposalBlock::ElectraBlinded(message) => {
            SignedBlock::Blinded(SignedBlindedProposalBlock::Electra(
                electra::SignedBlindedBeaconBlock { message, signature },
            ))
        }
        ProposalBlock::FuluBlinded(message) => {
            SignedBlock::Blinded(SignedBlindedProposalBlock::Fulu(
                electra::SignedBlindedBeaconBlock { message, signature },
            ))
        }
    }
}

async fn sign_with_proposer(
    signer: &super::SignFunc,
    pubkey: &BLSPubKey,
    client: &EthBeaconNodeApiClient,
    epoch: u64,
    message_root: Root,
) -> Result<BLSSignature> {
    let sig_data = get_data_root(client, DomainName::BeaconProposer, epoch, message_root).await?;
    Ok(signer.sign(pubkey, &sig_data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BeaconMock, ValidatorSet,
        validatormock::{EndpointMatch, SubmissionCapture},
    };
    use pluto_eth2api::spec::phase0::BLSPubKey;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path_regex},
    };

    /// Stub signer that copies the pubkey suffix into the signature so tests
    /// can assert the signed payload is non-zero. Mirrors the Go test helper
    /// (`copy(sig[:], key[:])`).
    #[derive(Debug)]
    struct StubSigner;
    impl super::super::Sign for StubSigner {
        fn sign(
            &self,
            pubkey: &BLSPubKey,
            _data: &[u8],
        ) -> std::result::Result<BLSSignature, super::super::SignError> {
            let mut sig = [0u8; 96];
            sig[..48].copy_from_slice(pubkey);
            Ok(sig)
        }
    }

    fn stub_signer() -> super::super::SignFunc {
        Arc::new(StubSigner)
    }

    fn padded_pubkey(seed: u8) -> BLSPubKey {
        [seed; 48]
    }

    fn padded_root(seed: u8) -> Root {
        [seed; 32]
    }

    fn sig_hex(seed: u8) -> String {
        format!("0x{}", hex::encode([seed; 96]))
    }

    /// Mounts a high-priority handler on `/eth/v3/validator/blocks/{slot}` that
    /// responds with `body`. Priority `1` mirrors `SubmissionCapture`.
    async fn mount_produce_block(server: &wiremock::MockServer, body: Value) {
        Mock::given(method("GET"))
            .and(path_regex(r"^/eth/v3/validator/blocks/[0-9]+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .with_priority(1)
            .mount(server)
            .await;
    }

    /// Mounts a POST handler for the validators endpoint mirroring the GET
    /// default served by [`BeaconMock`]. The client uses POST for filtered
    /// validator queries; [`super::super::active_validators`] dials that
    /// route. Priority `1` wins over any default.
    async fn mount_post_validators(server: &wiremock::MockServer, set: &ValidatorSet) {
        let body = json!({
            "data": set.validators(),
            "execution_optimistic": false,
            "finalized": false,
        });
        Mock::given(method("POST"))
            .and(path_regex(r"^/eth/v1/beacon/states/[^/]+/validators$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .with_priority(1)
            .mount(server)
            .await;
    }

    /// Constructs an Electra `BeaconBlock` JSON skeleton that round-trips
    /// through `electra::BeaconBlock`'s `Deserialize`.
    fn electra_block_value(slot: Slot, randao_seed: u8) -> Value {
        let empty: Vec<Value> = Vec::new();
        json!({
            "slot": slot.to_string(),
            "proposer_index": "1",
            "parent_root": format!("0x{}", hex::encode(padded_root(0x11))),
            "state_root": format!("0x{}", hex::encode(padded_root(0x22))),
            "body": {
                "randao_reveal": sig_hex(randao_seed),
                "eth1_data": {
                    "deposit_root": format!("0x{}", hex::encode(padded_root(0x33))),
                    "deposit_count": "0",
                    "block_hash": format!("0x{}", hex::encode(padded_root(0x44))),
                },
                "graffiti": format!("0x{}", hex::encode(padded_root(0x00))),
                "proposer_slashings": empty.clone(),
                "attester_slashings": empty.clone(),
                "attestations": empty.clone(),
                "deposits": empty.clone(),
                "voluntary_exits": empty.clone(),
                "sync_aggregate": {
                    "sync_committee_bits": format!("0x{}", "00".repeat(64)),
                    "sync_committee_signature": sig_hex(0x00),
                },
                "execution_payload": electra_execution_payload(),
                "bls_to_execution_changes": empty.clone(),
                "blob_kzg_commitments": empty,
                "execution_requests": {
                    "deposits": [],
                    "withdrawals": [],
                    "consolidations": [],
                },
            },
        })
    }

    fn electra_execution_payload() -> Value {
        json!({
            "parent_hash": format!("0x{}", hex::encode(padded_root(0x55))),
            "fee_recipient": format!("0x{}", "00".repeat(20)),
            "state_root": format!("0x{}", hex::encode(padded_root(0x66))),
            "receipts_root": format!("0x{}", hex::encode(padded_root(0x77))),
            "logs_bloom": format!("0x{}", "00".repeat(256)),
            "prev_randao": format!("0x{}", hex::encode(padded_root(0x88))),
            "block_number": "0",
            "gas_limit": "30000000",
            "gas_used": "0",
            "timestamp": "0",
            "extra_data": "0x",
            "base_fee_per_gas": "0",
            "block_hash": format!("0x{}", hex::encode(padded_root(0x99))),
            "transactions": [],
            "withdrawals": [],
            "blob_gas_used": "0",
            "excess_blob_gas": "0",
        })
    }

    fn electra_blinded_execution_payload_header() -> Value {
        json!({
            "parent_hash": format!("0x{}", hex::encode(padded_root(0x55))),
            "fee_recipient": format!("0x{}", "00".repeat(20)),
            "state_root": format!("0x{}", hex::encode(padded_root(0x66))),
            "receipts_root": format!("0x{}", hex::encode(padded_root(0x77))),
            "logs_bloom": format!("0x{}", "00".repeat(256)),
            "prev_randao": format!("0x{}", hex::encode(padded_root(0x88))),
            "block_number": "0",
            "gas_limit": "30000000",
            "gas_used": "0",
            "timestamp": "0",
            "extra_data": "0x",
            "base_fee_per_gas": "0",
            "block_hash": format!("0x{}", hex::encode(padded_root(0x99))),
            "transactions_root": format!("0x{}", hex::encode(padded_root(0xaa))),
            "withdrawals_root": format!("0x{}", hex::encode(padded_root(0xbb))),
            "blob_gas_used": "0",
            "excess_blob_gas": "0",
        })
    }

    fn electra_blinded_block_value(slot: Slot, randao_seed: u8) -> Value {
        let empty: Vec<Value> = Vec::new();
        json!({
            "slot": slot.to_string(),
            "proposer_index": "1",
            "parent_root": format!("0x{}", hex::encode(padded_root(0x11))),
            "state_root": format!("0x{}", hex::encode(padded_root(0x22))),
            "body": {
                "randao_reveal": sig_hex(randao_seed),
                "eth1_data": {
                    "deposit_root": format!("0x{}", hex::encode(padded_root(0x33))),
                    "deposit_count": "0",
                    "block_hash": format!("0x{}", hex::encode(padded_root(0x44))),
                },
                "graffiti": format!("0x{}", hex::encode(padded_root(0x00))),
                "proposer_slashings": empty.clone(),
                "attester_slashings": empty.clone(),
                "attestations": empty.clone(),
                "deposits": empty.clone(),
                "voluntary_exits": empty.clone(),
                "sync_aggregate": {
                    "sync_committee_bits": format!("0x{}", "00".repeat(64)),
                    "sync_committee_signature": sig_hex(0x00),
                },
                "execution_payload_header": electra_blinded_execution_payload_header(),
                "bls_to_execution_changes": empty.clone(),
                "blob_kzg_commitments": empty,
                "execution_requests": {
                    "deposits": [],
                    "withdrawals": [],
                    "consolidations": [],
                },
            },
        })
    }

    fn fork_epochs_at_zero_spec() -> Value {
        crate::default_spec_with(json!({
            "CONFIG_NAME": "charon-simnet",
            "SLOTS_PER_EPOCH": "16",
            "SECONDS_PER_SLOT": "12",
            "GENESIS_FORK_VERSION": "0x01017000",
            "ALTAIR_FORK_VERSION": "0x20000910",
            "ALTAIR_FORK_EPOCH": "0",
            "BELLATRIX_FORK_VERSION": "0x30000910",
            "BELLATRIX_FORK_EPOCH": "0",
            "CAPELLA_FORK_VERSION": "0x40000910",
            "CAPELLA_FORK_EPOCH": "0",
            "DENEB_FORK_VERSION": "0x50000910",
            "DENEB_FORK_EPOCH": "0",
            "ELECTRA_FORK_VERSION": "0x60000910",
            "ELECTRA_FORK_EPOCH": "0",
            "FULU_FORK_VERSION": "0x70000910",
            "FULU_FORK_EPOCH": "18446744073709551615",
            "DOMAIN_BEACON_PROPOSER": "0x00000000",
            "DOMAIN_BEACON_ATTESTER": "0x01000000",
            "DOMAIN_RANDAO": "0x02000000",
            "DOMAIN_DEPOSIT": "0x03000000",
            "DOMAIN_VOLUNTARY_EXIT": "0x04000000",
            "DOMAIN_SELECTION_PROOF": "0x05000000",
            "DOMAIN_AGGREGATE_AND_PROOF": "0x06000000",
            "DOMAIN_SYNC_COMMITTEE": "0x07000000",
            "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF": "0x08000000",
            "DOMAIN_CONTRIBUTION_AND_PROOF": "0x09000000",
            "DOMAIN_APPLICATION_BUILDER": "0x00000001",
            "EPOCHS_PER_SYNC_COMMITTEE_PERIOD": "256",
        }))
    }

    async fn electra_beacon_mock() -> BeaconMock {
        BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .deterministic_proposer_duties(0)
            .spec(fork_epochs_at_zero_spec())
            .build()
            .await
            .expect("build mock")
    }

    #[tokio::test]
    async fn propose_block_electra_full() {
        let mock = electra_beacon_mock().await;
        let slot: Slot = 0; // first slot in epoch 0, proposer = validator index 1

        let block = electra_block_value(slot, 0x42);
        let response_body = json!({
            "version": "electra",
            "execution_payload_blinded": false,
            "consensus_block_value": "1",
            "execution_payload_value": "1",
            "data": {
                "block": block,
                "kzg_proofs": [],
                "blobs": [],
            },
        });

        mount_post_validators(mock.server(), &ValidatorSet::validator_set_a()).await;
        mount_produce_block(mock.server(), response_body).await;

        let capture = SubmissionCapture::mount(
            mock.server(),
            "POST",
            EndpointMatch::path("/eth/v2/beacon/blocks"),
            json!({}),
        )
        .await;

        propose_block(mock.client(), &stub_signer(), slot)
            .await
            .expect("propose_block");

        let captured = capture.take();
        assert_eq!(
            captured.len(),
            1,
            "expected one POST to /eth/v2/beacon/blocks"
        );
        let signed_block = captured[0]
            .get("signed_block")
            .expect("signed_block in body");
        let signature = signed_block
            .get("signature")
            .and_then(Value::as_str)
            .expect("signature");
        assert_ne!(
            signature,
            format!("0x{}", "00".repeat(96)).as_str(),
            "signature must be non-zero",
        );
        let submitted_slot = signed_block
            .get("message")
            .and_then(|m| m.get("slot"))
            .and_then(Value::as_str);
        assert_eq!(submitted_slot, Some(slot.to_string().as_str()));
    }

    #[tokio::test]
    async fn propose_block_electra_blinded() {
        let mock = electra_beacon_mock().await;
        let slot: Slot = 0;

        let block = electra_blinded_block_value(slot, 0x42);
        let response_body = json!({
            "version": "electra",
            "execution_payload_blinded": true,
            "consensus_block_value": "1",
            "execution_payload_value": "1",
            "data": block,
        });

        mount_post_validators(mock.server(), &ValidatorSet::validator_set_a()).await;
        mount_produce_block(mock.server(), response_body).await;

        let capture = SubmissionCapture::mount(
            mock.server(),
            "POST",
            EndpointMatch::path("/eth/v2/beacon/blinded_blocks"),
            json!({}),
        )
        .await;

        propose_block(mock.client(), &stub_signer(), slot)
            .await
            .expect("propose_block blinded");

        let captured = capture.take();
        assert_eq!(
            captured.len(),
            1,
            "expected one POST to /eth/v2/beacon/blinded_blocks",
        );
        let signature = captured[0]
            .get("signature")
            .and_then(Value::as_str)
            .expect("signature");
        assert_ne!(
            signature,
            format!("0x{}", "00".repeat(96)).as_str(),
            "signature must be non-zero",
        );
    }

    #[tokio::test]
    async fn propose_block_fulu_full() {
        let mut spec = fork_epochs_at_zero_spec();
        if let Some(obj) = spec.as_object_mut() {
            obj.insert(
                "FULU_FORK_EPOCH".to_string(),
                Value::String("0".to_string()),
            );
        }
        let mock = BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .deterministic_proposer_duties(0)
            .spec(spec)
            .build()
            .await
            .expect("build mock");
        let slot: Slot = 0;

        // Fulu reuses Electra's BeaconBlock layout.
        let block = electra_block_value(slot, 0x84);
        let response_body = json!({
            "version": "fulu",
            "execution_payload_blinded": false,
            "consensus_block_value": "1",
            "execution_payload_value": "1",
            "data": {
                "block": block,
                "kzg_proofs": [],
                "blobs": [],
            },
        });

        mount_post_validators(mock.server(), &ValidatorSet::validator_set_a()).await;
        mount_produce_block(mock.server(), response_body).await;
        let capture = SubmissionCapture::mount(
            mock.server(),
            "POST",
            EndpointMatch::path("/eth/v2/beacon/blocks"),
            json!({}),
        )
        .await;

        propose_block(mock.client(), &stub_signer(), slot)
            .await
            .expect("propose_block fulu");

        assert_eq!(capture.len(), 1);
    }

    #[tokio::test]
    async fn propose_block_returns_when_not_proposer() {
        // Use slot that no active validator is responsible for; with
        // `deterministic_proposer_duties(0)` only the first slot of each epoch
        // is assigned, so slot 1 has no duty.
        let mock = electra_beacon_mock().await;
        let slot: Slot = 1;
        mount_post_validators(mock.server(), &ValidatorSet::validator_set_a()).await;

        // Should NOT hit /eth/v3/validator/blocks/{slot}. We mount a 500 to
        // verify; if propose_block proceeded, the call would fail.
        Mock::given(method("GET"))
            .and(path_regex(r"^/eth/v3/validator/blocks/[0-9]+$"))
            .respond_with(ResponseTemplate::new(500))
            .with_priority(1)
            .mount(mock.server())
            .await;

        propose_block(mock.client(), &stub_signer(), slot)
            .await
            .expect("propose_block must be a no-op when not the slot proposer");
    }

    #[tokio::test]
    async fn register_validator_v1_submits_signed_registration() {
        let mock = electra_beacon_mock().await;

        let pubkey = padded_pubkey(0xAB);
        let registration = VersionedSignedValidatorRegistration {
            version: BuilderVersion::V1,
            v1: Some(pluto_eth2api::v1::SignedValidatorRegistration {
                message: pluto_eth2api::v1::ValidatorRegistration {
                    fee_recipient: [0xCD; 20],
                    gas_limit: 30_000_000,
                    timestamp: 1_700_000_000,
                    pubkey,
                },
                signature: [0u8; 96],
            }),
        };

        let capture = SubmissionCapture::mount(
            mock.server(),
            "POST",
            EndpointMatch::path("/eth/v1/validator/register_validator"),
            json!({}),
        )
        .await;

        register(mock.client(), &stub_signer(), &registration, pubkey)
            .await
            .expect("register");

        let captured = capture.take();
        assert_eq!(
            captured.len(),
            1,
            "expected one POST to /eth/v1/validator/register_validator",
        );
        let registrations = captured[0].as_array().expect("array body");
        assert_eq!(registrations.len(), 1);
        let signature = registrations[0]
            .get("signature")
            .and_then(Value::as_str)
            .expect("signature");
        assert_ne!(
            signature,
            format!("0x{}", "00".repeat(96)).as_str(),
            "registration signature must be non-zero",
        );
        let message_pubkey = registrations[0]
            .get("message")
            .and_then(|m| m.get("pubkey"))
            .and_then(Value::as_str)
            .expect("pubkey");
        assert_eq!(
            message_pubkey,
            format!("0x{}", hex::encode(pubkey)).as_str(),
        );
    }

    // ---------------------------------------------------------------------
    // Variants whose `random*Proposal` fixtures don't exist in Pluto's
    // `testutil::random` module yet. Re-enable once those helpers land.
    // ---------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "TODO: no RandomCapellaVersionedProposal equivalent in pluto-testutil::random yet"]
    async fn propose_block_capella_full() {}

    #[tokio::test]
    #[ignore = "TODO: no RandomDenebVersionedProposal equivalent in pluto-testutil::random yet"]
    async fn propose_block_deneb_full() {}

    #[tokio::test]
    #[ignore = "TODO: no RandomCapellaBlindedBeaconBlock equivalent in pluto-testutil::random yet"]
    async fn propose_block_capella_blinded() {}

    #[tokio::test]
    #[ignore = "TODO: no RandomDenebBlindedBeaconBlock equivalent in pluto-testutil::random yet"]
    async fn propose_block_deneb_blinded() {}

    #[tokio::test]
    #[ignore = "TODO: no RandomBellatrixBlindedBeaconBlock equivalent in pluto-testutil::random yet"]
    async fn propose_blinded_block_bellatrix() {}

    #[tokio::test]
    #[ignore = "TODO: no RandomFuluBlindedBeaconBlock equivalent in pluto-testutil::random yet"]
    async fn propose_block_fulu_blinded() {}
}
