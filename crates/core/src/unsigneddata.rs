//! Unsigned duty data domain types and protobuf decoding.

use std::collections::HashMap;

use pluto_eth2api::spec::phase0;
use pluto_ssz::decode::{decode_u32, decode_u64};
use serde::{Deserialize, Deserializer, de};
use ssz::Decode;

use crate::{
    ParSigExCodecError,
    corepb::v1::core as pbcore,
    signeddata::{
        AttestationData, AttesterDuty, SyncContribution, VersionedAggregatedAttestation,
        VersionedProposal,
    },
    types::{DutyType, PubKey},
};

const ATTESTATION_DATA_SSZ_OFFSET: usize = 8;
const ATTESTER_DUTY_SSZ_SIZE: usize = 96;

/// Unsigned duty data variant — matches Go's `core.UnsignedData` interface.
#[derive(Debug, Clone)]
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

/// Converts an unsigned-data-set protobuf into domain unsigned duty data.
/// Currently decodes attester data; other duty types return unsupported.
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
        _ => Err(ParSigExCodecError::UnsupportedDutyType),
    }
}

fn decode_attestation_data(data: &[u8]) -> Result<AttestationData, ParSigExCodecError> {
    if let Ok(data) = decode_attestation_data_ssz(data) {
        return Ok(data);
    }

    if data.iter().find(|b| !b.is_ascii_whitespace()).copied() == Some(b'{') {
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
}
