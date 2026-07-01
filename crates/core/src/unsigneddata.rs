//! Unsigned duty data domain types and protobuf decoding.

use std::collections::HashMap;

use pluto_eth2api::spec::phase0;
use pluto_ssz::decode::{decode_u32, decode_u64};
use serde::{Deserialize, Deserializer, de};
use ssz::{Decode, Encode};

use crate::{
    ParSigExCodecError,
    corepb::v1::core as pbcore,
    parsigex_codec::looks_like_json,
    signeddata::{
        AttestationData, AttesterDuty, SyncContribution, VersionedAggregatedAttestation,
        VersionedProposal,
    },
    ssz_codec,
    types::{DutyType, PubKey},
};

const ATTESTATION_DATA_SSZ_OFFSET: usize = 8;
const ATTESTER_DUTY_SSZ_SIZE: usize = 96;

/// Unsigned duty data variant — matches Go's `core.UnsignedData` interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsignedDutyData {
    /// Unsigned proposal (DutyProposer).
    Proposal(Box<VersionedProposal>),
    /// Unsigned attestation data (DutyAttester).
    Attestation(AttestationData),
    /// Unsigned aggregated attestation (DutyAggregator).
    AggAttestation(VersionedAggregatedAttestation),
    /// Unsigned sync contribution (DutySyncContribution).
    SyncContribution(SyncContribution),
}

/// Map from public key to unsigned duty data, equivalent to Go's
/// `core.UnsignedDataSet`.
pub type UnsignedDataSet = HashMap<PubKey, UnsignedDutyData>;

/// Converts a domain unsigned-data-set into its protobuf wire form.
///
/// Mirrors charon's `UnsignedDataSetToProto` + `marshal`: every supported
/// unsigned-data type is SSZ-capable, and charon enables SSZ marshalling by
/// default (since v0.17), so each entry is encoded as SSZ binary using the
/// byte layout from `charon/core/ssz.go`. The decode counterpart
/// ([`unsigned_duty_data_from_proto`]) accepts both SSZ and the legacy JSON
/// encoding, matching charon's `unmarshal`.
pub fn unsigned_data_set_to_proto(
    set: &UnsignedDataSet,
) -> Result<pbcore::UnsignedDataSet, ParSigExCodecError> {
    let mut inner = std::collections::BTreeMap::new();
    for (pubkey, data) in set {
        inner.insert(pubkey.to_string(), marshal_unsigned_duty_data(data)?.into());
    }

    Ok(pbcore::UnsignedDataSet { set: inner })
}

/// SSZ-marshals a single unsigned duty data value, matching charon's `marshal`
/// (SSZ-first; every variant here is SSZ-capable).
fn marshal_unsigned_duty_data(data: &UnsignedDutyData) -> Result<Vec<u8>, ParSigExCodecError> {
    Ok(match data {
        UnsignedDutyData::Attestation(att) => encode_attestation_data_ssz(att)?,
        UnsignedDutyData::Proposal(proposal) => ssz_codec::encode_versioned_proposal(proposal)?,
        UnsignedDutyData::AggAttestation(agg) => {
            ssz_codec::encode_versioned_aggregated_attestation(agg)?
        }
        UnsignedDutyData::SyncContribution(contribution) => {
            ssz_codec::encode_sync_contribution(contribution)?
        }
    })
}

/// SSZ-encodes an [`AttestationData`] using charon's layout:
/// `offset(4)=8 + offset(4) + AttestationData SSZ + AttesterDuty SSZ`, where
/// the `AttesterDuty` body is a 48-byte zero pubkey followed by six
/// little-endian `u64` fields (`charon/core/ssz.go` `attesterDutySSZ`). The
/// leading pubkey is zeroed because pluto's [`AttesterDuty`] omits it (it is
/// recovered from the aggregation bits downstream), matching the attester
/// decode path.
///
/// This is hand-rolled rather than derived with `ssz_derive` on purpose: charon
/// emits a two-slot offset table (`4 + 4`) here even though both
/// `AttestationData` and `AttesterDuty` are *fixed*-size (`charon/core/ssz.go`
/// `AttestationData.MarshalSSZTo`). `ssz_derive` omits offsets for all-fixed
/// containers, so a derived `{data, duty}` struct would drop the 8-byte prefix
/// and break wire-compat. (Contrast the Deneb+ block contents in `ssz_codec`,
/// whose fields are all variable-length, so deriving is correct there.)
fn encode_attestation_data_ssz(att: &AttestationData) -> Result<Vec<u8>, ParSigExCodecError> {
    let overflow = || ParSigExCodecError::UnsignedData("attestation data too large".to_string());

    let attestation = att.data.as_ssz_bytes();
    let data_offset = ATTESTATION_DATA_SSZ_OFFSET;
    let duty_offset = data_offset
        .checked_add(attestation.len())
        .ok_or_else(overflow)?;
    let capacity = duty_offset
        .checked_add(ATTESTER_DUTY_SSZ_SIZE)
        .ok_or_else(overflow)?;
    let data_offset = u32::try_from(data_offset).map_err(|_| overflow())?;
    let duty_offset = u32::try_from(duty_offset).map_err(|_| overflow())?;

    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&data_offset.to_le_bytes());
    out.extend_from_slice(&duty_offset.to_le_bytes());
    out.extend_from_slice(&attestation);
    // AttesterDuty: 48-byte pubkey (zeroed) + 6 u64 fields.
    out.extend_from_slice(&[0u8; 48]);
    out.extend_from_slice(&att.duty.slot.to_le_bytes());
    out.extend_from_slice(&att.duty.validator_index.to_le_bytes());
    out.extend_from_slice(&att.duty.committee_index.to_le_bytes());
    out.extend_from_slice(&att.duty.committee_length.to_le_bytes());
    out.extend_from_slice(&att.duty.committees_at_slot.to_le_bytes());
    out.extend_from_slice(&att.duty.validator_committee_index.to_le_bytes());
    Ok(out)
}

/// Converts an unsigned-data-set protobuf into domain unsigned duty data.
pub fn unsigned_data_set_from_proto(
    duty_type: &DutyType,
    set: &pbcore::UnsignedDataSet,
) -> Result<UnsignedDataSet, ParSigExCodecError> {
    if set.set.is_empty() {
        return Err(ParSigExCodecError::InvalidUnsignedDataSetFields);
    }

    let mut out = UnsignedDataSet::with_capacity(set.set.len());
    for (pubkey, data) in &set.set {
        let pubkey = PubKey::try_from(pubkey.as_str())
            .map_err(|_| ParSigExCodecError::InvalidPubKey(pubkey.clone()))?;
        out.insert(pubkey, unsigned_duty_data_from_proto(duty_type, data)?);
    }

    Ok(out)
}

fn unsigned_duty_data_from_proto(
    duty_type: &DutyType,
    data: &[u8],
) -> Result<UnsignedDutyData, ParSigExCodecError> {
    match duty_type {
        DutyType::Attester => decode_attestation_data(data).map(UnsignedDutyData::Attestation),
        DutyType::Proposer => decode_versioned_proposal(data)
            .map(Box::new)
            .map(UnsignedDutyData::Proposal),
        DutyType::Aggregator => {
            decode_aggregated_attestation(data).map(UnsignedDutyData::AggAttestation)
        }
        DutyType::SyncContribution => {
            decode_sync_contribution(data).map(UnsignedDutyData::SyncContribution)
        }
        _ => Err(ParSigExCodecError::UnsupportedDutyType),
    }
}

/// Decodes an unsigned [`VersionedProposal`], SSZ-first with JSON fallback
/// (charon `DutyProposer` branch of `unmarshalUnsignedData`).
fn decode_versioned_proposal(data: &[u8]) -> Result<VersionedProposal, ParSigExCodecError> {
    if let Ok(proposal) = ssz_codec::decode_versioned_proposal(data) {
        return Ok(proposal);
    }

    if looks_like_json(data) {
        // Reuses `VersionedProposal`'s `Deserialize` impl (shared per-fork JSON
        // dispatch in `signeddata`).
        return serde_json::from_slice(data).map_err(ParSigExCodecError::from);
    }

    Err(ParSigExCodecError::UnsignedData(
        "unmarshal proposal".to_string(),
    ))
}

/// Decodes an unsigned aggregated attestation, SSZ-first with JSON fallback
/// (charon `DutyAggregator` branch). Charon tries the *versioned* aggregated
/// attestation first, then falls back to the non-versioned
/// `AggregatedAttestation` (a raw `phase0::Attestation`). Pluto only models the
/// versioned variant, so a non-versioned attestation is wrapped as a phase0
/// versioned attestation (functionally equivalent).
fn decode_aggregated_attestation(
    data: &[u8],
) -> Result<VersionedAggregatedAttestation, ParSigExCodecError> {
    if let Ok(agg) = ssz_codec::decode_versioned_aggregated_attestation(data) {
        return Ok(agg);
    }
    if let Ok(att) = phase0::Attestation::from_ssz_bytes(data) {
        return Ok(wrap_phase0_aggregated_attestation(att));
    }

    if looks_like_json(data) {
        if let Ok(decoded) = serde_json::from_slice::<crate::signeddata::VersionedAttestation>(data)
        {
            return Ok(VersionedAggregatedAttestation(decoded.0));
        }
        let att: phase0::Attestation =
            serde_json::from_slice(data).map_err(ParSigExCodecError::from)?;
        return Ok(wrap_phase0_aggregated_attestation(att));
    }

    Err(ParSigExCodecError::UnsignedData(
        "unmarshal aggregated attestation".to_string(),
    ))
}

/// Wraps a non-versioned phase0 attestation as a phase0
/// [`VersionedAggregatedAttestation`].
fn wrap_phase0_aggregated_attestation(att: phase0::Attestation) -> VersionedAggregatedAttestation {
    use pluto_eth2api::versioned::{AttestationPayload, DataVersion, VersionedAttestation};
    VersionedAggregatedAttestation(VersionedAttestation {
        version: DataVersion::Phase0,
        validator_index: None,
        attestation: Some(AttestationPayload::Phase0(att)),
    })
}

/// Decodes an unsigned [`SyncContribution`], SSZ-first with JSON fallback
/// (charon `DutySyncContribution` branch).
fn decode_sync_contribution(data: &[u8]) -> Result<SyncContribution, ParSigExCodecError> {
    if let Ok(contribution) = ssz_codec::decode_sync_contribution(data) {
        return Ok(contribution);
    }

    if looks_like_json(data) {
        let contribution = serde_json::from_slice(data).map_err(ParSigExCodecError::from)?;
        return Ok(SyncContribution(contribution));
    }

    Err(ParSigExCodecError::UnsignedData(
        "unmarshal sync contribution".to_string(),
    ))
}

fn decode_attestation_data(data: &[u8]) -> Result<AttestationData, ParSigExCodecError> {
    if let Ok(data) = decode_attestation_data_ssz(data) {
        return Ok(data);
    }

    if looks_like_json(data) {
        let decoded: AttestationDataJson =
            serde_json::from_slice(data).map_err(ParSigExCodecError::from)?;
        return Ok(AttestationData {
            data: decoded.attestation_data,
            duty: decoded.attestation_duty.into(),
        });
    }

    Err(ParSigExCodecError::UnsignedData(
        "unmarshal attestation data".to_string(),
    ))
}

fn decode_attestation_data_ssz(data: &[u8]) -> Result<AttestationData, ParSigExCodecError> {
    if data.len() < ATTESTATION_DATA_SSZ_OFFSET {
        return Err(ParSigExCodecError::UnsignedData(
            "attestation data too short".to_string(),
        ));
    }

    let data_offset = usize::try_from(
        decode_u32(&data[..4]).map_err(|err| ParSigExCodecError::UnsignedData(err.to_string()))?,
    )
    .map_err(|err| ParSigExCodecError::UnsignedData(err.to_string()))?;
    let duty_offset = usize::try_from(
        decode_u32(&data[4..ATTESTATION_DATA_SSZ_OFFSET])
            .map_err(|err| ParSigExCodecError::UnsignedData(err.to_string()))?,
    )
    .map_err(|err| ParSigExCodecError::UnsignedData(err.to_string()))?;

    if data_offset != ATTESTATION_DATA_SSZ_OFFSET
        || duty_offset < data_offset
        || duty_offset > data.len()
        || data.len().saturating_sub(duty_offset) < ATTESTER_DUTY_SSZ_SIZE
    {
        return Err(ParSigExCodecError::UnsignedData(
            "attestation data offset".to_string(),
        ));
    }

    let attestation_data = phase0::AttestationData::from_ssz_bytes(&data[data_offset..duty_offset])
        .map_err(|err| ParSigExCodecError::UnsignedData(format!("{err:?}")))?;
    let duty = decode_attester_duty_ssz(&data[duty_offset..])?;

    Ok(AttestationData {
        data: attestation_data,
        duty,
    })
}

fn decode_attester_duty_ssz(data: &[u8]) -> Result<AttesterDuty, ParSigExCodecError> {
    if data.len() < ATTESTER_DUTY_SSZ_SIZE {
        return Err(ParSigExCodecError::UnsignedData(
            "attester duty too short".to_string(),
        ));
    }

    let field = |start, end| {
        decode_u64(&data[start..end])
            .map_err(|err| ParSigExCodecError::UnsignedData(err.to_string()))
    };

    Ok(AttesterDuty {
        slot: field(48, 56)?,
        validator_index: field(56, 64)?,
        committee_index: field(64, 72)?,
        committee_length: field(72, 80)?,
        committees_at_slot: field(80, 88)?,
        validator_committee_index: field(88, 96)?,
    })
}

#[derive(Deserialize)]
struct AttestationDataJson {
    attestation_data: phase0::AttestationData,
    attestation_duty: AttesterDutyJson,
}

#[derive(Deserialize)]
struct AttesterDutyJson {
    #[serde(deserialize_with = "deserialize_u64")]
    slot: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    validator_index: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    committee_index: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    committee_length: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    committees_at_slot: u64,
    #[serde(deserialize_with = "deserialize_u64")]
    validator_committee_index: u64,
}

impl From<AttesterDutyJson> for AttesterDuty {
    fn from(value: AttesterDutyJson) -> Self {
        Self {
            slot: value.slot,
            validator_index: value.validator_index,
            committee_index: value.committee_index,
            committee_length: value.committee_length,
            committees_at_slot: value.committees_at_slot,
            validator_committee_index: value.validator_committee_index,
        }
    }
}

fn deserialize_u64<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| de::Error::custom("invalid u64 number")),
        serde_json::Value::String(string) => string.parse().map_err(de::Error::custom),
        _ => Err(de::Error::custom("expected u64 string or number")),
    }
}

#[cfg(test)]
mod tests {
    use prost::bytes::Bytes;
    use ssz::Encode;

    use super::*;
    use crate::testutils::random_core_pub_key;

    const TEST_ATTESTATION_DATA_SSZ_OFFSET: usize = 8;
    const TEST_ATTESTER_DUTY_SSZ_SIZE: usize = 96;

    #[test]
    fn unsigned_data_set_from_proto_decodes_attester_ssz() {
        let pubkey = random_core_pub_key();
        let data = att_data(123, 4, 5);
        let proto = unsigned_attestation_proto(pubkey, &data);

        let decoded = unsigned_data_set_from_proto(&DutyType::Attester, &proto).unwrap();

        match decoded.get(&pubkey).unwrap() {
            UnsignedDutyData::Attestation(decoded) => assert_eq!(decoded, &data),
            other => panic!("unexpected unsigned data: {other:?}"),
        }
    }

    #[test]
    fn unsigned_data_set_from_proto_decodes_attester_json() {
        let pubkey = random_core_pub_key();
        let data = att_data(123, 4, 5);
        let proto = unsigned_attestation_json_proto(pubkey, &data);

        let decoded = unsigned_data_set_from_proto(&DutyType::Attester, &proto).unwrap();

        match decoded.get(&pubkey).unwrap() {
            UnsignedDutyData::Attestation(decoded) => assert_eq!(decoded, &data),
            other => panic!("unexpected unsigned data: {other:?}"),
        }
    }

    #[test]
    fn unsigned_data_set_from_proto_rejects_empty_set() {
        let err =
            unsigned_data_set_from_proto(&DutyType::Attester, &pbcore::UnsignedDataSet::default())
                .unwrap_err();

        assert!(matches!(
            err,
            ParSigExCodecError::InvalidUnsignedDataSetFields
        ));
    }

    fn att_data(slot: u64, committee_index: u64, validator_index: u64) -> AttestationData {
        AttestationData {
            data: phase0::AttestationData {
                slot,
                index: committee_index,
                beacon_block_root: [0u8; 32],
                source: phase0::Checkpoint::default(),
                target: phase0::Checkpoint::default(),
            },
            duty: AttesterDuty {
                slot,
                validator_index,
                committee_index,
                committee_length: 8,
                committees_at_slot: 1,
                validator_committee_index: validator_index,
            },
        }
    }

    fn unsigned_attestation_proto(
        pubkey: PubKey,
        data: &AttestationData,
    ) -> pbcore::UnsignedDataSet {
        pbcore::UnsignedDataSet {
            set: [(pubkey.to_string(), attestation_proto_bytes(data))].into(),
        }
    }

    fn attestation_proto_bytes(data: &AttestationData) -> Bytes {
        let attestation = data.data.as_ssz_bytes();
        let duty_offset = TEST_ATTESTATION_DATA_SSZ_OFFSET
            .checked_add(attestation.len())
            .expect("test attestation offset fits usize");
        let capacity = duty_offset
            .checked_add(TEST_ATTESTER_DUTY_SSZ_SIZE)
            .expect("test attestation proto length fits usize");
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(
            &u32::try_from(TEST_ATTESTATION_DATA_SSZ_OFFSET)
                .expect("test attestation offset fits u32")
                .to_le_bytes(),
        );
        out.extend_from_slice(
            &u32::try_from(duty_offset)
                .expect("test duty offset fits u32")
                .to_le_bytes(),
        );
        out.extend_from_slice(&attestation);
        out.extend_from_slice(&[0; 48]);
        out.extend_from_slice(&data.duty.slot.to_le_bytes());
        out.extend_from_slice(&data.duty.validator_index.to_le_bytes());
        out.extend_from_slice(&data.duty.committee_index.to_le_bytes());
        out.extend_from_slice(&data.duty.committee_length.to_le_bytes());
        out.extend_from_slice(&data.duty.committees_at_slot.to_le_bytes());
        out.extend_from_slice(&data.duty.validator_committee_index.to_le_bytes());
        Bytes::from(out)
    }

    fn unsigned_attestation_json_proto(
        pubkey: PubKey,
        data: &AttestationData,
    ) -> pbcore::UnsignedDataSet {
        let value = serde_json::json!({
            "attestation_data": data.data,
            "attestation_duty": {
                "slot": data.duty.slot.to_string(),
                "validator_index": data.duty.validator_index.to_string(),
                "committee_index": data.duty.committee_index.to_string(),
                "committee_length": data.duty.committee_length.to_string(),
                "committees_at_slot": data.duty.committees_at_slot.to_string(),
                "validator_committee_index": data.duty.validator_committee_index.to_string(),
            },
        });
        pbcore::UnsignedDataSet {
            set: [(
                pubkey.to_string(),
                Bytes::from(serde_json::to_vec(&value).unwrap()),
            )]
            .into(),
        }
    }

    // ── all-duty-type round trips ──────────────────────────────────────

    use pluto_eth2api::{
        spec::{altair, phase0 as p0},
        versioned,
    };
    use pluto_ssz::{BitList, BitVector};

    use crate::signeddata::{ProposalBlock, SyncContribution, VersionedAggregatedAttestation};

    /// The SSZ encoder must reproduce charon's `AttestationData` byte layout —
    /// it must be identical to the standalone test helper (which mirrors
    /// `charon/core/ssz.go`), so peers and pluto agree on the wire bytes.
    #[test]
    fn attester_ssz_encoding_matches_charon_layout() {
        let data = att_data(123, 4, 5);
        assert_eq!(
            encode_attestation_data_ssz(&data).unwrap(),
            attestation_proto_bytes(&data).to_vec()
        );
    }

    fn sample_versioned_proposal_phase0(slot: u64) -> VersionedProposal {
        let block = p0::BeaconBlock {
            slot,
            proposer_index: 2,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: p0::BeaconBlockBody {
                randao_reveal: [0x33; 96],
                eth1_data: p0::ETH1Data {
                    deposit_root: [0x44; 32],
                    deposit_count: 0,
                    block_hash: [0x55; 32],
                },
                graffiti: [0x66; 32],
                proposer_slashings: vec![].into(),
                attester_slashings: vec![].into(),
                attestations: vec![].into(),
                deposits: vec![].into(),
                voluntary_exits: vec![].into(),
            },
        };
        VersionedProposal {
            block: ProposalBlock::Phase0(block),
            consensus_block_value: alloy::primitives::U256::ZERO,
            execution_payload_value: alloy::primitives::U256::ZERO,
        }
    }

    fn sample_versioned_aggregated_attestation() -> VersionedAggregatedAttestation {
        VersionedAggregatedAttestation(versioned::VersionedAttestation {
            version: versioned::DataVersion::Deneb,
            validator_index: None,
            attestation: Some(versioned::AttestationPayload::Deneb(p0::Attestation {
                aggregation_bits: BitList::with_bits(16, &[1, 3]),
                data: att_data(99, 7, 8).data,
                signature: [0x77; 96],
            })),
        })
    }

    fn sample_sync_contribution() -> SyncContribution {
        SyncContribution(altair::SyncCommitteeContribution {
            slot: 200,
            beacon_block_root: [0xab; 32],
            subcommittee_index: 2,
            aggregation_bits: BitVector::with_bits(&[0, 5]),
            signature: [0xcd; 96],
        })
    }

    /// Encodes a single-entry [`UnsignedDataSet`] and decodes it back for the
    /// given duty type, asserting the round trip preserves the value.
    fn assert_round_trip(duty_type: DutyType, pubkey: PubKey, data: UnsignedDutyData) {
        let mut set = UnsignedDataSet::new();
        set.insert(pubkey, data.clone());

        let proto = unsigned_data_set_to_proto(&set).unwrap();
        let decoded = unsigned_data_set_from_proto(&duty_type, &proto).unwrap();

        // Default-marshalling is SSZ (charon parity): the entry must not be JSON.
        let bytes = proto.set.get(&pubkey.to_string()).unwrap();
        assert_ne!(bytes.first(), Some(&b'{'), "default encoding must be SSZ");

        assert_eq!(decoded.get(&pubkey), Some(&data));
    }

    #[test]
    fn round_trip_attester() {
        let pubkey = random_core_pub_key();
        assert_round_trip(
            DutyType::Attester,
            pubkey,
            UnsignedDutyData::Attestation(att_data(123, 4, 5)),
        );
    }

    #[test]
    fn round_trip_proposer() {
        let pubkey = random_core_pub_key();
        assert_round_trip(
            DutyType::Proposer,
            pubkey,
            UnsignedDutyData::Proposal(Box::new(sample_versioned_proposal_phase0(42))),
        );
    }

    #[test]
    fn round_trip_aggregator() {
        let pubkey = random_core_pub_key();
        assert_round_trip(
            DutyType::Aggregator,
            pubkey,
            UnsignedDutyData::AggAttestation(sample_versioned_aggregated_attestation()),
        );
    }

    #[test]
    fn round_trip_sync_contribution() {
        let pubkey = random_core_pub_key();
        assert_round_trip(
            DutyType::SyncContribution,
            pubkey,
            UnsignedDutyData::SyncContribution(sample_sync_contribution()),
        );
    }

    /// Regression: `SyncCommitteeContribution` is a fixed-size SSZ container
    /// whose leading field is a little-endian `u64` slot, so its SSZ encoding
    /// begins with `0x7B` (`{`) whenever `slot % 256 == 123`. A
    /// `{`-prefix-first dispatch would misroute such a valid SSZ payload to
    /// JSON and fail; charon tries SSZ first (`core/proto.go` `unmarshal`),
    /// so this must round-trip.
    #[test]
    fn sync_contribution_ssz_leading_brace_round_trips() {
        let contribution = SyncContribution(altair::SyncCommitteeContribution {
            slot: 0x7B, // little-endian u64 → first SSZ byte is `{`
            beacon_block_root: [0xab; 32],
            subcommittee_index: 2,
            aggregation_bits: BitVector::with_bits(&[0, 5]),
            signature: [0xcd; 96],
        });

        // The SSZ encoding really does begin with `{` (the flaw's trigger).
        let encoded = ssz_codec::encode_sync_contribution(&contribution).unwrap();
        assert_eq!(
            encoded.first(),
            Some(&b'{'),
            "leading SSZ byte should be 0x7B"
        );

        let pubkey = random_core_pub_key();
        let mut set = UnsignedDataSet::new();
        set.insert(
            pubkey,
            UnsignedDutyData::SyncContribution(contribution.clone()),
        );

        let proto = unsigned_data_set_to_proto(&set).unwrap();
        let decoded = unsigned_data_set_from_proto(&DutyType::SyncContribution, &proto).unwrap();

        assert_eq!(
            decoded.get(&pubkey),
            Some(&UnsignedDutyData::SyncContribution(contribution)),
        );
    }

    /// The proposer JSON fallback (legacy, pre-SSZ charon) decodes the
    /// `{version, block, blinded}` wrapper.
    #[test]
    fn proposer_json_fallback_decodes() {
        let pubkey = random_core_pub_key();
        let proposal = sample_versioned_proposal_phase0(7);
        let ProposalBlock::Phase0(block) = &proposal.block else {
            panic!("expected phase0 block");
        };
        let value = serde_json::json!({
            "version": "phase0",
            "blinded": false,
            "block": block,
        });
        let proto = pbcore::UnsignedDataSet {
            set: [(
                pubkey.to_string(),
                Bytes::from(serde_json::to_vec(&value).unwrap()),
            )]
            .into(),
        };

        let decoded = unsigned_data_set_from_proto(&DutyType::Proposer, &proto).unwrap();
        match decoded.get(&pubkey).unwrap() {
            UnsignedDutyData::Proposal(decoded) => assert_eq!(decoded.block, proposal.block),
            other => panic!("unexpected unsigned data: {other:?}"),
        }
    }

    /// The aggregator JSON fallback decodes the
    /// `{version, validator_index, attestation}` wrapper.
    #[test]
    fn aggregator_json_fallback_decodes() {
        let pubkey = random_core_pub_key();
        let agg = sample_versioned_aggregated_attestation();
        let versioned::AttestationPayload::Deneb(att) = agg.0.attestation.as_ref().unwrap() else {
            panic!("expected deneb attestation");
        };
        let value = serde_json::json!({
            "version": "deneb",
            "attestation": att,
        });
        let proto = pbcore::UnsignedDataSet {
            set: [(
                pubkey.to_string(),
                Bytes::from(serde_json::to_vec(&value).unwrap()),
            )]
            .into(),
        };

        let decoded = unsigned_data_set_from_proto(&DutyType::Aggregator, &proto).unwrap();
        match decoded.get(&pubkey).unwrap() {
            UnsignedDutyData::AggAttestation(decoded) => assert_eq!(decoded, &agg),
            other => panic!("unexpected unsigned data: {other:?}"),
        }
    }

    /// The sync-contribution JSON fallback decodes the bare contribution
    /// object.
    #[test]
    fn sync_contribution_json_fallback_decodes() {
        let pubkey = random_core_pub_key();
        let contribution = sample_sync_contribution();
        let proto = pbcore::UnsignedDataSet {
            set: [(
                pubkey.to_string(),
                Bytes::from(serde_json::to_vec(&contribution.0).unwrap()),
            )]
            .into(),
        };

        let decoded = unsigned_data_set_from_proto(&DutyType::SyncContribution, &proto).unwrap();
        match decoded.get(&pubkey).unwrap() {
            UnsignedDutyData::SyncContribution(decoded) => assert_eq!(decoded, &contribution),
            other => panic!("unexpected unsigned data: {other:?}"),
        }
    }

    /// A non-versioned (raw phase0) aggregated attestation — what older charon
    /// nodes send — decodes into a phase0 [`VersionedAggregatedAttestation`].
    #[test]
    fn aggregator_non_versioned_ssz_fallback() {
        let pubkey = random_core_pub_key();
        let att = p0::Attestation {
            aggregation_bits: BitList::with_bits(8, &[0, 2]),
            data: att_data(55, 1, 2).data,
            signature: [0x99; 96],
        };
        let proto = pbcore::UnsignedDataSet {
            set: [(pubkey.to_string(), Bytes::from(att.as_ssz_bytes()))].into(),
        };

        let decoded = unsigned_data_set_from_proto(&DutyType::Aggregator, &proto).unwrap();
        match decoded.get(&pubkey).unwrap() {
            UnsignedDutyData::AggAttestation(decoded) => {
                assert_eq!(decoded.0.version, versioned::DataVersion::Phase0);
                assert_eq!(
                    decoded.0.attestation,
                    Some(versioned::AttestationPayload::Phase0(att))
                );
            }
            other => panic!("unexpected unsigned data: {other:?}"),
        }
    }

    #[test]
    fn unsigned_data_set_to_proto_round_trips_full_set() {
        // Two attester entries in a single set survive an encode→decode round
        // trip, exercising the map plumbing in `unsigned_data_set_to_proto`.
        let pk1 = random_core_pub_key();
        let pk2 = random_core_pub_key();
        let mut set = UnsignedDataSet::new();
        set.insert(pk1, UnsignedDutyData::Attestation(att_data(1, 2, 3)));
        set.insert(pk2, UnsignedDutyData::Attestation(att_data(4, 5, 6)));

        let proto = unsigned_data_set_to_proto(&set).unwrap();
        assert_eq!(proto.set.len(), 2);
        let decoded = unsigned_data_set_from_proto(&DutyType::Attester, &proto).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.get(&pk1), set.get(&pk1));
        assert_eq!(decoded.get(&pk2), set.get(&pk2));
    }
}
