//! Proto ↔ domain conversions for FROST round messages.

use std::collections::HashMap;

use pluto_crypto::types::{G1_COMPRESSED_LENGTH, SCALAR_LENGTH};
use pluto_frost::{
    G1Projective,
    kryptology::{self, Round1Bcast, Round2Bcast, ShamirShare},
};
use prost::bytes::Bytes;

use crate::{
    dkgpb::v1::frost::{
        FrostMsgKey, FrostRound1Cast, FrostRound1Casts, FrostRound1P2p, FrostRound1ShamirShare,
        FrostRound2Cast, FrostRound2Casts,
    },
    frost::{FrostError, MsgKey},
};

pub(super) type Round1Response = (HashMap<MsgKey, Round1Bcast>, HashMap<MsgKey, ShamirShare>);

pub(super) fn key_to_proto(key: MsgKey) -> FrostMsgKey {
    FrostMsgKey {
        val_idx: key.val_idx,
        source_id: key.source_id,
        target_id: key.target_id,
    }
}

pub(super) fn key_from_proto(key: Option<&FrostMsgKey>) -> Result<MsgKey, FrostError> {
    let key = key.ok_or(FrostError::MissingMsgKey)?;
    Ok(MsgKey {
        val_idx: key.val_idx,
        source_id: key.source_id,
        target_id: key.target_id,
    })
}

pub(super) fn round1_cast_to_proto(key: MsgKey, cast: &Round1Bcast) -> FrostRound1Cast {
    FrostRound1Cast {
        key: Some(key_to_proto(key)),
        wi: Bytes::copy_from_slice(&cast.wi),
        ci: Bytes::copy_from_slice(&cast.ci),
        commitments: cast
            .commitments
            .iter()
            .map(|commitment| Bytes::copy_from_slice(commitment))
            .collect(),
    }
}

pub(super) fn round1_cast_from_proto(
    cast: &FrostRound1Cast,
) -> Result<(MsgKey, Round1Bcast), FrostError> {
    let wi = bytes_to_scalar(|| FrostError::DecodeWiScalar, &cast.wi)?;
    let ci = bytes_to_scalar(|| FrostError::DecodeC1Scalar, &cast.ci)?;
    let commitments = cast
        .commitments
        .iter()
        .map(|commitment| bytes_to_g1(|| FrostError::DecodeCommitment, commitment))
        .collect::<Result<Vec<_>, _>>()?;
    let key = key_from_proto(cast.key.as_ref())?;
    Ok((
        key,
        Round1Bcast {
            commitments,
            wi,
            ci,
        },
    ))
}

pub(super) fn shamir_share_to_proto(key: MsgKey, share: &ShamirShare) -> FrostRound1ShamirShare {
    FrostRound1ShamirShare {
        key: Some(key_to_proto(key)),
        id: share.id,
        value: Bytes::copy_from_slice(&share.value),
    }
}

pub(super) fn shamir_share_from_proto(
    share: &FrostRound1ShamirShare,
) -> Result<(MsgKey, ShamirShare), FrostError> {
    let key = key_from_proto(share.key.as_ref())?;
    let value = bytes_to_scalar(|| FrostError::DecodeShamirScalar, &share.value)?;
    Ok((
        key,
        ShamirShare {
            id: share.id,
            value,
        },
    ))
}

pub(super) fn round2_cast_to_proto(key: MsgKey, cast: &Round2Bcast) -> FrostRound2Cast {
    FrostRound2Cast {
        key: Some(key_to_proto(key)),
        verification_key: Bytes::copy_from_slice(&cast.verification_key),
        vk_share: Bytes::copy_from_slice(&cast.vk_share),
    }
}

pub(super) fn round2_cast_from_proto(
    cast: &FrostRound2Cast,
) -> Result<(MsgKey, Round2Bcast), FrostError> {
    let verification_key = bytes_to_g1(
        || FrostError::DecodeVerificationKeyScalar,
        &cast.verification_key,
    )?;
    let vk_share = bytes_to_g1(|| FrostError::DecodeVkShare, &cast.vk_share)?;
    let key = key_from_proto(cast.key.as_ref())?;
    Ok((
        key,
        Round2Bcast {
            verification_key,
            vk_share,
        },
    ))
}

pub(super) fn build_round1_casts(cast_r1: &HashMap<MsgKey, Round1Bcast>) -> FrostRound1Casts {
    FrostRound1Casts {
        casts: cast_r1
            .iter()
            .map(|(key, cast)| round1_cast_to_proto(*key, cast))
            .collect(),
    }
}

pub(super) fn build_round2_casts(cast_r2: &HashMap<MsgKey, Round2Bcast>) -> FrostRound2Casts {
    FrostRound2Casts {
        casts: cast_r2
            .iter()
            .map(|(key, cast)| round2_cast_to_proto(*key, cast))
            .collect(),
    }
}

pub(super) fn make_round1_response(
    casts: Vec<FrostRound1Casts>,
    p2ps: Vec<FrostRound1P2p>,
) -> Result<Round1Response, FrostError> {
    let mut cast_map = HashMap::new();
    let mut p2p_map = HashMap::new();

    for msg in &casts {
        for cast in &msg.casts {
            let (key, cast) = round1_cast_from_proto(cast)?;
            cast_map.insert(key, cast);
        }
    }
    for msg in &p2ps {
        for share in &msg.shares {
            let (key, share) = shamir_share_from_proto(share)?;
            p2p_map.insert(key, share);
        }
    }

    Ok((cast_map, p2p_map))
}

pub(super) fn make_round2_response(
    msgs: Vec<FrostRound2Casts>,
) -> Result<HashMap<MsgKey, Round2Bcast>, FrostError> {
    let mut cast_map = HashMap::new();
    for msg in &msgs {
        for cast in &msg.casts {
            let (key, cast) = round2_cast_from_proto(cast)?;
            cast_map.insert(key, cast);
        }
    }

    Ok(cast_map)
}

fn bytes_to_scalar(context: fn() -> FrostError, bytes: &Bytes) -> Result<[u8; 32], FrostError> {
    let scalar = bytes_to_array::<SCALAR_LENGTH>(context, bytes)?;
    kryptology::scalar_from_be(&scalar).map_err(|_| context())?;
    Ok(scalar)
}

fn bytes_to_g1(
    context: fn() -> FrostError,
    bytes: &Bytes,
) -> Result<[u8; G1_COMPRESSED_LENGTH], FrostError> {
    let point = bytes_to_array::<G1_COMPRESSED_LENGTH>(context, bytes)?;
    G1Projective::from_compressed(&point).ok_or_else(context)?;
    Ok(point)
}

fn bytes_to_array<const N: usize>(
    context: fn() -> FrostError,
    bytes: &Bytes,
) -> Result<[u8; N], FrostError> {
    bytes.as_ref().try_into().map_err(|_| context())
}

#[cfg(test)]
mod tests {
    use prost::Name;

    use super::*;

    #[test]
    fn frost_type_urls_use_dkg_package() {
        assert_eq!(
            FrostRound1Casts::type_url(),
            "type.googleapis.com/dkg.dkgpb.v1.FrostRound1Casts"
        );
        assert_eq!(
            FrostRound2Casts::type_url(),
            "type.googleapis.com/dkg.dkgpb.v1.FrostRound2Casts"
        );
    }

    #[test]
    fn key_round_trip() {
        let key = MsgKey {
            val_idx: 2,
            source_id: 3,
            target_id: 4,
        };

        assert_eq!(key_from_proto(Some(&key_to_proto(key))).unwrap(), key);
    }

    #[test]
    fn missing_key_is_rejected() {
        assert!(matches!(
            key_from_proto(None),
            Err(FrostError::MissingMsgKey)
        ));
    }

    #[test]
    fn invalid_scalar_is_rejected() {
        let cast = FrostRound1Cast {
            key: Some(key_to_proto(MsgKey {
                val_idx: 0,
                source_id: 1,
                target_id: 0,
            })),
            wi: Bytes::from_static(&[0xff; 32]),
            ci: Bytes::from_static(&[1; 32]),
            commitments: vec![],
        };

        assert!(matches!(
            round1_cast_from_proto(&cast),
            Err(FrostError::DecodeWiScalar)
        ));
    }

    #[test]
    fn invalid_point_is_rejected() {
        let cast = FrostRound2Cast {
            key: Some(key_to_proto(MsgKey {
                val_idx: 0,
                source_id: 1,
                target_id: 0,
            })),
            verification_key: Bytes::from(vec![42; 48]),
            vk_share: Bytes::from(vec![42; 48]),
        };

        assert!(matches!(
            round2_cast_from_proto(&cast),
            Err(FrostError::DecodeVerificationKeyScalar)
        ));
    }
}
