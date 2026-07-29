//! Block proposal + builder registration drivers.
//!
//! Rust port of `charon/testutil/validatormock/propose.go`. Mirrors the Go
//! [`ProposeBlock`] flow: fetch active validators, locate the slot proposer
//! via the proposer-duties endpoint, build a randao reveal, fetch the block
//! from `produce_block_v3`, sign its tree-hash root with
//! `DomainBeaconProposer`, and POST the signed block (or signed blinded block)
//! back. Also ports [`Register`] for builder validator registrations using
//! `DomainApplicationBuilder` over epoch 0.
//!
//! The Go code carries Phase0/Altair branches that the Pluto Rust client
//! surface barely supports today; those branches return
//! [`Error::UnsupportedVariant`] until typed support lands. The Bellatrix ->
//! Fulu range — and their blinded variants — is implemented in full.

use pluto_eth2api::{
    BlockRequestBody, BlockRequestBodyObject, BlockRequestBodyObject2, BlockRequestBodyObject3,
    BlockRequestBodyObject4, BlockRequestBodyObject5, ConsensusVersion,
    DenebSignedBlockContentsSignedBlock, EthBeaconNodeApiClient,
    GetBlindedBlockResponseResponseData, GetBlindedBlockResponseResponseDataObject,
    GetBlindedBlockResponseResponseDataObject2, GetBlindedBlockResponseResponseDataObject3,
    GetBlindedBlockResponseResponseDataObject4, GetProposerDutiesRequest,
    GetProposerDutiesResponse, ProduceBlockV3Request, ProduceBlockV3Response,
    ProduceBlockV3ResponseResponse, PublishBlindedBlockV2Request, PublishBlockV2Request,
    PublishBlockV2Response, RegisterValidatorRequest, RegisterValidatorRequestBodyItem,
    RegisterValidatorResponse, SignedBlockContentsSignedBlock, SignedValidatorRegistrationMessage,
    spec::{
        BuilderVersion, bellatrix, capella, deneb, electra,
        phase0::{BLSPubKey, BLSSignature, Root, Slot},
    },
    versioned::VersionedSignedValidatorRegistration,
};
use pluto_eth2util::{
    helpers::epoch_from_slot,
    signing::{DomainName, get_data_root},
    types::SignedEpoch,
};
use serde_json::Value;
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

    let request = GetProposerDutiesRequest::builder()
        .epoch(epoch.to_string())
        .build()
        .map_err(|err| Error::Malformed(format!("build proposer duties request: {err}")))?;

    let duties = match client.get_proposer_duties(request).await {
        Ok(GetProposerDutiesResponse::Ok(resp)) => resp.data,
        Ok(_) => return Err(Error::Malformed("proposer duties response".to_string())),
        Err(err) => return Err(Error::Malformed(format!("proposer duties: {err}"))),
    };

    let Some(duty) = duties.iter().find(|d| d.slot == slot.to_string()) else {
        // Go returns nil when this validator is not the slot proposer.
        return Ok(());
    };
    let pubkey = parse_pubkey(&duty.pubkey)?;

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
    let proposal_request = ProduceBlockV3Request::builder()
        .slot(slot.to_string())
        .randao_reveal(format_signature(randao))
        .build()
        .map_err(|err| Error::Malformed(format!("build produce-block request: {err}")))?;

    let proposal_resp = match client.produce_block_v3(proposal_request).await {
        Ok(ProduceBlockV3Response::Ok(resp)) => resp,
        Ok(_) => {
            return Err(Error::Malformed(
                "produce-block-v3 non-success response".to_string(),
            ));
        }
        Err(err) => {
            return Err(Error::Malformed(format!(
                "vmock beacon block proposal: {err}"
            )));
        }
    };

    let version = proposal_resp.version.clone();
    let blinded = proposal_resp.execution_payload_blinded;

    if blinded {
        let body = build_blinded_body(&proposal_resp, &pubkey, signer, client, epoch).await?;
        let request = PublishBlindedBlockV2Request::builder()
            .eth_consensus_version(version)
            .body(body)
            .build()
            .map_err(|err| Error::Malformed(format!("build blinded-publish request: {err}")))?;

        match client.publish_blinded_block_v2(request).await {
            Ok(PublishBlockV2Response::Ok | PublishBlockV2Response::Accepted) => Ok(()),
            Ok(_) => Err(Error::Malformed(
                "publish-blinded-block-v2 unexpected response".to_string(),
            )),
            Err(err) => Err(Error::Malformed(format!("publish-blinded-block-v2: {err}"))),
        }
    } else {
        let body = build_block_body(&proposal_resp, &pubkey, signer, client, epoch).await?;
        let request = PublishBlockV2Request::builder()
            .eth_consensus_version(version)
            .body(body)
            .build()
            .map_err(|err| Error::Malformed(format!("build publish-block request: {err}")))?;

        match client.publish_block_v2(request).await {
            Ok(PublishBlockV2Response::Ok | PublishBlockV2Response::Accepted) => Ok(()),
            Ok(_) => Err(Error::Malformed(
                "publish-block-v2 unexpected response".to_string(),
            )),
            Err(err) => Err(Error::Malformed(format!("publish-block-v2: {err}"))),
        }
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
            let body_item = RegisterValidatorRequestBodyItem {
                message: SignedValidatorRegistrationMessage {
                    fee_recipient: format!("0x{}", hex::encode(inner.message.fee_recipient)),
                    gas_limit: inner.message.gas_limit.to_string(),
                    pubkey: format!("0x{}", hex::encode(inner.message.pubkey)),
                    timestamp: inner.message.timestamp.to_string(),
                },
                signature: format_signature(sig),
            };
            let request = RegisterValidatorRequest::builder()
                .body(vec![body_item])
                .build()
                .map_err(|err| Error::Malformed(format!("build register request: {err}")))?;

            match client.register_validator(request).await {
                Ok(RegisterValidatorResponse::Ok) => Ok(()),
                Ok(_) => Err(Error::Malformed(
                    "register-validator unexpected response".to_string(),
                )),
                Err(err) => Err(Error::Malformed(format!("register-validator: {err}"))),
            }
        }
        BuilderVersion::Unknown => Err(Error::UnsupportedVariant("registration version")),
    }
}

async fn build_block_body(
    resp: &ProduceBlockV3ResponseResponse,
    pubkey: &BLSPubKey,
    signer: &super::SignFunc,
    client: &EthBeaconNodeApiClient,
    epoch: u64,
) -> Result<BlockRequestBody> {
    let block_value = serde_json::to_value(&resp.data)
        .map_err(|err| Error::Malformed(format!("serialise produce-block data: {err}")))?;

    match resp.version {
        ConsensusVersion::Capella => {
            let block: capella::BeaconBlock = json_from_value(&block_value)?;
            let root = block.tree_hash_root().0;
            let signature = sign_with_proposer(signer, pubkey, client, epoch, root).await?;
            Ok(BlockRequestBody::Object4(BlockRequestBodyObject4 {
                message: json_to_value(&block)?,
                signature: format_signature(signature),
            }))
        }
        ConsensusVersion::Deneb => {
            let inner = block_field(&block_value)?;
            let block: deneb::BeaconBlock = json_from_value(inner)?;
            let root = block.tree_hash_root().0;
            let signature = sign_with_proposer(signer, pubkey, client, epoch, root).await?;
            Ok(BlockRequestBody::Object3(BlockRequestBodyObject3 {
                blobs: json_array_strings(&block_value, "blobs"),
                kzg_proofs: json_array_strings(&block_value, "kzg_proofs"),
                signed_block: DenebSignedBlockContentsSignedBlock {
                    message: json_to_value(&block)?,
                    signature: format_signature(signature),
                },
            }))
        }
        ConsensusVersion::Electra => {
            let inner = block_field(&block_value)?;
            let block: electra::BeaconBlock = json_from_value(inner)?;
            let root = block.tree_hash_root().0;
            let signature = sign_with_proposer(signer, pubkey, client, epoch, root).await?;
            Ok(BlockRequestBody::Object2(BlockRequestBodyObject2 {
                blobs: json_array_strings(&block_value, "blobs"),
                kzg_proofs: json_array_strings(&block_value, "kzg_proofs"),
                signed_block: SignedBlockContentsSignedBlock {
                    message: json_to_value(&block)?,
                    signature: format_signature(signature),
                },
            }))
        }
        ConsensusVersion::Fulu => {
            // Fulu reuses the Electra BeaconBlock layout.
            let inner = block_field(&block_value)?;
            let block: electra::BeaconBlock = json_from_value(inner)?;
            let root = block.tree_hash_root().0;
            let signature = sign_with_proposer(signer, pubkey, client, epoch, root).await?;
            Ok(BlockRequestBody::Object(BlockRequestBodyObject {
                blobs: json_array_strings(&block_value, "blobs"),
                kzg_proofs: json_array_strings(&block_value, "kzg_proofs"),
                signed_block: SignedBlockContentsSignedBlock {
                    message: json_to_value(&block)?,
                    signature: format_signature(signature),
                },
            }))
        }
        ConsensusVersion::Bellatrix => {
            let block: bellatrix::BeaconBlock = json_from_value(&block_value)?;
            let root = block.tree_hash_root().0;
            let signature = sign_with_proposer(signer, pubkey, client, epoch, root).await?;
            Ok(BlockRequestBody::Object5(BlockRequestBodyObject5 {
                message: json_to_value(&block)?,
                signature: format_signature(signature),
            }))
        }
        ConsensusVersion::Phase0 | ConsensusVersion::Altair => {
            Err(Error::UnsupportedVariant("phase0/altair block"))
        }
    }
}

async fn build_blinded_body(
    resp: &ProduceBlockV3ResponseResponse,
    pubkey: &BLSPubKey,
    signer: &super::SignFunc,
    client: &EthBeaconNodeApiClient,
    epoch: u64,
) -> Result<GetBlindedBlockResponseResponseData> {
    let block_value = serde_json::to_value(&resp.data)
        .map_err(|err| Error::Malformed(format!("serialise produce-block data: {err}")))?;

    match resp.version {
        ConsensusVersion::Bellatrix => {
            let block: bellatrix::BlindedBeaconBlock = json_from_value(&block_value)?;
            let root = block.tree_hash_root().0;
            let signature = sign_with_proposer(signer, pubkey, client, epoch, root).await?;
            Ok(GetBlindedBlockResponseResponseData::Object4(
                GetBlindedBlockResponseResponseDataObject4 {
                    message: json_to_value(&block)?,
                    signature: format_signature(signature),
                },
            ))
        }
        ConsensusVersion::Capella => {
            let block: capella::BlindedBeaconBlock = json_from_value(&block_value)?;
            let root = block.tree_hash_root().0;
            let signature = sign_with_proposer(signer, pubkey, client, epoch, root).await?;
            Ok(GetBlindedBlockResponseResponseData::Object3(
                GetBlindedBlockResponseResponseDataObject3 {
                    message: json_to_value(&block)?,
                    signature: format_signature(signature),
                },
            ))
        }
        ConsensusVersion::Deneb => {
            let block: deneb::BlindedBeaconBlock = json_from_value(&block_value)?;
            let root = block.tree_hash_root().0;
            let signature = sign_with_proposer(signer, pubkey, client, epoch, root).await?;
            Ok(GetBlindedBlockResponseResponseData::Object2(
                GetBlindedBlockResponseResponseDataObject2 {
                    message: json_to_value(&block)?,
                    signature: format_signature(signature),
                },
            ))
        }
        ConsensusVersion::Electra | ConsensusVersion::Fulu => {
            // Go aliases Fulu blinded to Electra's blinded block type, so both
            // map onto Pluto's Electra blinded variant.
            let block: electra::BlindedBeaconBlock = json_from_value(&block_value)?;
            let root = block.tree_hash_root().0;
            let signature = sign_with_proposer(signer, pubkey, client, epoch, root).await?;
            Ok(GetBlindedBlockResponseResponseData::Object(
                GetBlindedBlockResponseResponseDataObject {
                    message: json_to_value(&block)?,
                    signature: format_signature(signature),
                },
            ))
        }
        ConsensusVersion::Phase0 | ConsensusVersion::Altair => {
            Err(Error::UnsupportedVariant("phase0/altair blinded block"))
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

fn parse_pubkey(s: &str) -> Result<BLSPubKey> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|err| Error::Malformed(err.to_string()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed(format!("pubkey length {} != 48", bytes.len())))
}

fn format_signature(sig: BLSSignature) -> String {
    format!("0x{}", hex::encode(sig))
}

fn json_from_value<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T> {
    serde_json::from_value(value.clone())
        .map_err(|err| Error::Malformed(format!("decode block message: {err}")))
}

fn json_to_value<T: serde::Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value)
        .map_err(|err| Error::Malformed(format!("encode signed block: {err}")))
}

fn block_field(value: &Value) -> Result<&Value> {
    value.get("block").ok_or_else(|| {
        Error::Malformed("missing `block` field in produce-block response".to_string())
    })
}

fn json_array_strings(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
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
    /// default served by [`BeaconMock`]. The generated client uses POST for
    /// filtered validator queries; [`super::super::active_validators`] dials
    /// that route. Priority `1` wins over any default.
    async fn mount_post_validators(server: &wiremock::MockServer, set: &ValidatorSet) {
        let data: Vec<Value> = set
            .validators()
            .into_iter()
            .map(|validator| {
                json!({
                    "index": validator.index.to_string(),
                    "balance": validator.balance.to_string(),
                    "status": validator.status,
                    "validator": validator.validator,
                })
            })
            .collect();
        let body = json!({
            "data": data,
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
        json!({
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
        })
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
