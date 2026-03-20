use pluto_eth2api::spec::phase0;
use serde::{Deserialize, Serialize};
use tree_hash_derive::TreeHash;

/// Signature of a corresponding epoch.
#[serde_with::serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SignedEpoch {
    /// Epoch value.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub epoch: phase0::Epoch,
    /// BLS signature for the epoch.
    #[tree_hash(skip_hashing)]
    #[serde_as(as = "pluto_eth2api::spec::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    #[test]
    fn signed_epoch_hash_root() {
        let epoch = SignedEpoch {
            epoch: 42,
            signature: [0x11; phase0::BLS_SIGNATURE_LEN],
        };

        assert_eq!(
            hex::encode(epoch.tree_hash_root()),
            "2a00000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn signed_epoch_json_roundtrip() {
        let epoch = SignedEpoch {
            epoch: 42,
            signature: [0x11; phase0::BLS_SIGNATURE_LEN],
        };

        let json = serde_json::to_string(&epoch).expect("marshal signed epoch");
        assert_eq!(
            json,
            format!(
                "{{\"epoch\":\"42\",\"signature\":\"0x{}\"}}",
                hex::encode(epoch.signature)
            )
        );

        let roundtrip: SignedEpoch = serde_json::from_str(&json).expect("unmarshal signed epoch");
        assert_eq!(roundtrip, epoch);
    }

    #[test]
    fn signed_epoch_accepts_unprefixed_signature() {
        let sig_hex = hex::encode([0x11; phase0::BLS_SIGNATURE_LEN]);
        let json = format!("{{\"epoch\":\"42\",\"signature\":\"{sig_hex}\"}}");
        let epoch: SignedEpoch =
            serde_json::from_str(&json).expect("unprefixed hex should be accepted");
        assert_eq!(epoch.signature, [0x11; phase0::BLS_SIGNATURE_LEN]);
    }
}
