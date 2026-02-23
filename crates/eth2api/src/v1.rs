//! API v1 types from the Ethereum beacon chain and builder API specifications.

use tree_hash_derive::TreeHash;

use crate::spec::{bellatrix::ExecutionAddress, phase0::BLSPubKey};

/// Validator registration message for the builder API.
///
/// See: <https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/builder.md#validatorregistrationv1>
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct ValidatorRegistration {
    /// Fee recipient address (20 bytes).
    pub fee_recipient: ExecutionAddress,
    /// Gas limit.
    pub gas_limit: u64,
    /// Registration timestamp in unix seconds.
    pub timestamp: u64,
    /// Validator BLS public key (48 bytes).
    pub pubkey: BLSPubKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    #[test]
    fn validator_registration_tree_hash() {
        let reg = ValidatorRegistration {
            fee_recipient: [0xAA; 20],
            gas_limit: 30_000_000,
            timestamp: 1_000_000,
            pubkey: [0xBB; 48],
        };

        let root = reg.tree_hash_root();
        let expected =
            hex::decode("51334aceeda4bd921bad529aa54c00536d02950213c44da638ef541efe024d5e")
                .unwrap();
        assert_eq!(root.0, expected.as_slice());
    }
}
