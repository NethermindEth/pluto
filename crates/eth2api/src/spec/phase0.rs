//! Phase 0 consensus types from the Ethereum beacon chain specification.
//!
//! See: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md>
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tree_hash::TreeHash;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

pub use pluto_ssz::{BitList, SszList, SszVector};

/// Fork version length in bytes.
pub const VERSION_LEN: usize = 4;
/// Signature domain length in bytes.
pub const DOMAIN_LEN: usize = 32;
/// Domain type length in bytes.
pub const DOMAIN_TYPE_LEN: usize = 4;
/// Merkle root length in bytes.
pub const ROOT_LEN: usize = 32;
/// Withdrawal credentials length in bytes.
pub const WITHDRAWAL_CREDENTIALS_LEN: usize = 32;
/// BLS public key length in bytes.
pub const BLS_PUBKEY_LEN: usize = 48;
/// BLS signature length in bytes.
pub const BLS_SIGNATURE_LEN: usize = 96;
/// Number of branch elements in a deposit proof.
pub const DEPOSIT_PROOF_LEN: usize = 33;
/// Maximum number of proposer slashings per block.
pub const MAX_PROPOSER_SLASHINGS: usize = 16;
/// Maximum number of attester slashings per block.
pub const MAX_ATTESTER_SLASHINGS: usize = 2;
/// Maximum number of attestations per block.
pub const MAX_ATTESTATIONS: usize = 128;
/// Maximum number of deposits per block.
pub const MAX_DEPOSITS: usize = 16;
/// Maximum number of voluntary exits per block.
pub const MAX_VOLUNTARY_EXITS: usize = 16;
/// Maximum number of validators in a committee.
pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2_048;

/// An amount in Gwei.
pub type Gwei = u64;

/// A validator registry index.
pub type ValidatorIndex = u64;

/// An epoch number.
pub type Epoch = u64;

/// A slot number.
pub type Slot = u64;

/// A fork version number.
pub type Version = [u8; VERSION_LEN];

/// A signature domain.
pub type Domain = [u8; DOMAIN_LEN];

/// A domain type.
pub type DomainType = [u8; DOMAIN_TYPE_LEN];

/// A Merkle root.
pub type Root = [u8; ROOT_LEN];

/// A 32-byte execution hash.
pub type Hash32 = [u8; ROOT_LEN];

/// Withdrawal credentials.
pub type WithdrawalCredentials = [u8; WITHDRAWAL_CREDENTIALS_LEN];

/// A BLS12-381 public key.
pub type BLSPubKey = [u8; BLS_PUBKEY_LEN];

/// A BLS12-381 signature.
pub type BLSSignature = [u8; BLS_SIGNATURE_LEN];

/// Deposit message.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#depositmessage>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct DepositMessage {
    /// BLS public key.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub pubkey: BLSPubKey,
    /// Withdrawal credentials.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub withdrawal_credentials: WithdrawalCredentials,
    /// Amount in Gwei.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub amount: Gwei,
}

impl From<&DepositData> for DepositMessage {
    fn from(data: &DepositData) -> Self {
        DepositMessage {
            pubkey: data.pubkey,
            withdrawal_credentials: data.withdrawal_credentials,
            amount: data.amount,
        }
    }
}

/// Deposit data.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#depositdata>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct DepositData {
    /// BLS public key.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub pubkey: BLSPubKey,
    /// Withdrawal credentials.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub withdrawal_credentials: WithdrawalCredentials,
    /// Amount in Gwei.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub amount: Gwei,
    /// BLS signature.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: BLSSignature,
}

/// Fork data.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#forkdata>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct ForkData {
    /// Current fork version.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub current_version: Version,
    /// Genesis validators root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub genesis_validators_root: Root,
}

/// Signing data.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#signingdata>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct SigningData {
    /// Object root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub object_root: Root,
    /// Signature domain.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub domain: Domain,
}

impl SignedVoluntaryExit {
    /// Returns the SSZ message root of the unsigned voluntary exit.
    pub fn message_root(&self) -> Root {
        self.message.tree_hash_root().0
    }
}

/// ETH1 voting data.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#eth1data>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct ETH1Data {
    /// Deposit tree root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub deposit_root: Root,
    /// Deposit count at the voted ETH1 block.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub deposit_count: u64,
    /// ETH1 block hash.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub block_hash: Hash32,
}

/// Beacon block header.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#beaconblockheader>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    /// Block slot.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub slot: Slot,
    /// Proposer validator index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub proposer_index: ValidatorIndex,
    /// Parent root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub parent_root: Root,
    /// State root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub state_root: Root,
    /// Body root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub body_root: Root,
}

/// Signed beacon block header.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#signedbeaconblockheader>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct SignedBeaconBlockHeader {
    /// Unsigned beacon block header.
    pub message: BeaconBlockHeader,
    /// Signature over the header.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: BLSSignature,
}

/// Proposer slashing container.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#proposerslashing>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct ProposerSlashing {
    /// First conflicting signed header.
    pub signed_header_1: SignedBeaconBlockHeader,
    /// Second conflicting signed header.
    pub signed_header_2: SignedBeaconBlockHeader,
}

/// Indexed attestation.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#indexedattestation>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct IndexedAttestation {
    /// Indices of attesting validators.
    #[serde(with = "pluto_ssz::serde_utils::ssz_list_u64_string_serde")]
    pub attesting_indices: SszList<ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE>,
    /// Attestation data.
    pub data: AttestationData,
    /// Aggregate signature.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: BLSSignature,
}

/// Attester slashing container.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#attesterslashing>
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct AttesterSlashing {
    /// First conflicting indexed attestation.
    pub attestation_1: IndexedAttestation,
    /// Second conflicting indexed attestation.
    pub attestation_2: IndexedAttestation,
}

/// Deposit operation container.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#deposit>
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct Deposit {
    /// Merkle proof branch.
    pub proof: SszVector<Root, DEPOSIT_PROOF_LEN>,
    /// Deposit data.
    pub data: DepositData,
}

/// Phase0 beacon block body.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#beaconblockbody>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct BeaconBlockBody {
    /// RANDAO reveal.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub randao_reveal: BLSSignature,
    /// ETH1 data vote.
    pub eth1_data: ETH1Data,
    /// Graffiti bytes.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub graffiti: Root,
    /// Proposer slashings included in the block.
    pub proposer_slashings: SszList<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    /// Attester slashings included in the block.
    pub attester_slashings: SszList<AttesterSlashing, MAX_ATTESTER_SLASHINGS>,
    /// Attestations included in the block.
    pub attestations: SszList<Attestation, MAX_ATTESTATIONS>,
    /// Deposits included in the block.
    pub deposits: SszList<Deposit, MAX_DEPOSITS>,
    /// Voluntary exits included in the block.
    pub voluntary_exits: SszList<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
}

/// Phase0 beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#beaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct BeaconBlock {
    /// Block slot.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub slot: Slot,
    /// Proposer validator index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub proposer_index: ValidatorIndex,
    /// Parent root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub parent_root: Root,
    /// State root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub state_root: Root,
    /// Block body.
    pub body: BeaconBlockBody,
}

/// Signed phase0 beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#signedbeaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct SignedBeaconBlock {
    /// Unsigned block message.
    pub message: BeaconBlock,
    /// Signature of the message.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: BLSSignature,
}

/// A checkpoint in the beacon chain.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#checkpoint>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Epoch associated with the checkpoint.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub epoch: Epoch,
    /// Root of the checkpoint.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub root: Root,
}

/// Attestation data.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#attestationdata>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct AttestationData {
    /// Slot for the attestation.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub slot: Slot,
    /// Committee index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub index: u64,
    /// Beacon block root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub beacon_block_root: Root,
    /// Source checkpoint.
    pub source: Checkpoint,
    /// Target checkpoint.
    pub target: Checkpoint,
}

/// Attestation object.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#attestation>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct Attestation {
    /// Aggregation bits.
    pub aggregation_bits: BitList<2048>,
    /// Attestation data.
    pub data: AttestationData,
    /// Aggregate signature.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: BLSSignature,
}

/// Aggregate-and-proof payload.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/validator.md#aggregateandproof>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct AggregateAndProof {
    /// Aggregator validator index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub aggregator_index: ValidatorIndex,
    /// Aggregate attestation.
    pub aggregate: Attestation,
    /// Selection proof.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub selection_proof: BLSSignature,
}

/// Signed aggregate-and-proof payload.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/validator.md#signedaggregateandproof>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct SignedAggregateAndProof {
    /// Unsigned message.
    pub message: AggregateAndProof,
    /// Signature of the message.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: BLSSignature,
}

/// Voluntary exit message.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#voluntaryexit>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct VoluntaryExit {
    /// Exit epoch.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub epoch: Epoch,
    /// Validator index requesting exit.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_index: ValidatorIndex,
}

/// Signed voluntary exit message.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#signedvoluntaryexit>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct SignedVoluntaryExit {
    /// Unsigned voluntary exit message.
    pub message: VoluntaryExit,
    /// Signature of the message.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: BLSSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures;
    use test_case::test_case;
    use tree_hash::TreeHash;

    fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex::decode(hex).expect("invalid hex");
        bytes.try_into().expect("wrong length")
    }

    fn assert_tree_hash<T: TreeHash>(value: &T, expected_hex: &str) {
        let expected = hex_to_bytes::<32>(expected_hex);
        let actual = value.tree_hash_root();
        assert_eq!(actual, expected, "tree hash mismatch");
    }

    #[test]
    fn type_sizes() {
        assert_eq!(std::mem::size_of::<BLSPubKey>(), BLS_PUBKEY_LEN);
        assert_eq!(std::mem::size_of::<BLSSignature>(), BLS_SIGNATURE_LEN);
        assert_eq!(std::mem::size_of::<Domain>(), DOMAIN_LEN);
        assert_eq!(std::mem::size_of::<Root>(), ROOT_LEN);
        assert_eq!(std::mem::size_of::<Version>(), VERSION_LEN);
        assert_eq!(
            std::mem::size_of::<WithdrawalCredentials>(),
            WITHDRAWAL_CREDENTIALS_LEN
        );
        assert_eq!(std::mem::size_of::<Gwei>(), 8);
    }

    #[test]
    fn deposit_message_conversion() {
        let deposit_data = DepositData {
            pubkey: [1u8; BLS_PUBKEY_LEN],
            withdrawal_credentials: [2u8; WITHDRAWAL_CREDENTIALS_LEN],
            amount: 32_000_000_000,
            signature: [3u8; BLS_SIGNATURE_LEN],
        };

        let deposit_message = DepositMessage::from(&deposit_data);

        assert_eq!(deposit_message.pubkey, deposit_data.pubkey);
        assert_eq!(
            deposit_message.withdrawal_credentials,
            deposit_data.withdrawal_credentials
        );
        assert_eq!(deposit_message.amount, deposit_data.amount);
    }

    #[test]
    fn deposit_data_tree_hash() {
        let deposit_data = DepositData {
            pubkey: hex_to_bytes(
                "8bb5476559fc3ef444be1a5b4d6f5d1f8c8b6f8e8c8a8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f9a9b9c9d9e9fa0a1a2a3",
            ),
            withdrawal_credentials: hex_to_bytes(
                "010000000000000000000000abcdef1234567890abcdef1234567890abcdef12",
            ),
            amount: 32_000_000_000,
            signature: hex_to_bytes(
                "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5f6a7b8c9d0e1f2a3b4c5d6",
            ),
        };

        assert_tree_hash(
            &deposit_data,
            "d194c30f5e55f27b0896c6d66ad40cc72e093a71c0afc35bfa7cc6d0ec13417c",
        );
    }

    #[test]
    fn deposit_message_tree_hash() {
        let deposit_message = DepositMessage {
            pubkey: hex_to_bytes(
                "8bb5476559fc3ef444be1a5b4d6f5d1f8c8b6f8e8c8a8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f9a9b9c9d9e9fa0a1a2a3",
            ),
            withdrawal_credentials: hex_to_bytes(
                "010000000000000000000000abcdef1234567890abcdef1234567890abcdef12",
            ),
            amount: 32_000_000_000,
        };

        assert_tree_hash(
            &deposit_message,
            "89ce9bfbbba12f5f3c8939186623506852eb49122d5c18af80165d41a7947a82",
        );
    }

    #[test]
    fn fork_data_tree_hash() {
        let fork_data = ForkData {
            current_version: hex_to_bytes("01020304"),
            genesis_validators_root: hex_to_bytes(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            ),
        };

        assert_tree_hash(
            &fork_data,
            "35f90ce5dd9afeb16dde0939ca9c9d22ab35f3c4b88749048ff87bdf654ddfbf",
        );
    }

    #[test]
    fn signing_data_tree_hash() {
        let signing_data = SigningData {
            object_root: hex_to_bytes(
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            ),
            domain: hex_to_bytes(
                "0300000001020304000000000000000000000000000000000000000000000000",
            ),
        };

        assert_tree_hash(
            &signing_data,
            "6ad6de7d10b1bfddd4dccb3835df79f08a3fbe478a9894e817e48f24545ae2ec",
        );
    }

    #[test]
    fn attestation_data_tree_hash_vector() {
        let data = AttestationData {
            slot: 1,
            index: 2,
            beacon_block_root: [0x11; 32],
            source: Checkpoint {
                epoch: 3,
                root: [0x22; 32],
            },
            target: Checkpoint {
                epoch: 4,
                root: [0x33; 32],
            },
        };

        assert_tree_hash(
            &data,
            "0e2611469670519087ad67c1374a94cbe148b165117d396b93f344636a702ba6",
        );
    }

    #[test]
    fn attestation_tree_hash_vector() {
        let data = AttestationData {
            slot: 1,
            index: 2,
            beacon_block_root: [0x11; 32],
            source: Checkpoint {
                epoch: 3,
                root: [0x22; 32],
            },
            target: Checkpoint {
                epoch: 4,
                root: [0x33; 32],
            },
        };

        let aggregation_bits = BitList::<2048>::with_bits(8, &[0]);

        let attestation = Attestation {
            aggregation_bits,
            data,
            signature: [0x44; 96],
        };

        assert_tree_hash(
            &attestation,
            "a8daa382f9475b7dc006f17d8f346fc6478dadaba5c67f3115a825a6886b3595",
        );
    }

    #[test]
    fn aggregate_and_proof_tree_hash_vector() {
        let data = AttestationData {
            slot: 1,
            index: 2,
            beacon_block_root: [0x11; 32],
            source: Checkpoint {
                epoch: 3,
                root: [0x22; 32],
            },
            target: Checkpoint {
                epoch: 4,
                root: [0x33; 32],
            },
        };

        let aggregation_bits = BitList::<2048>::with_bits(8, &[0]);

        let aggregate_and_proof = AggregateAndProof {
            aggregator_index: 7,
            aggregate: Attestation {
                aggregation_bits,
                data,
                signature: [0x44; 96],
            },
            selection_proof: [0x55; 96],
        };

        assert_tree_hash(
            &aggregate_and_proof,
            "ed20e5f79897447b03e31d2f89548acb66bb694fe177118539bb85f09d4b5073",
        );
    }

    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::phase0_deposit_fixture()),
        test_fixtures::VECTORS.phase0_deposit_root;
        "deposit_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::phase0_beacon_block_body_fixture()),
        test_fixtures::VECTORS.phase0_beacon_block_body_root;
        "beacon_block_body_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::phase0_beacon_block_fixture()),
        test_fixtures::VECTORS.phase0_beacon_block_root;
        "beacon_block_root"
    )]
    fn tree_hash_matches_vector(actual: String, expected: &'static str) {
        assert_eq!(actual, expected);
    }

    #[test]
    fn ssz_vector_bounds_are_enforced_on_deposit_proof_deserialize() {
        let proof: Vec<Root> = (1_u8..=34).map(test_fixtures::seq::<32>).collect();
        let deposit = Deposit {
            proof: SszVector(proof),
            data: DepositData {
                pubkey: test_fixtures::seq::<48>(0x10),
                withdrawal_credentials: test_fixtures::seq::<32>(0x20),
                amount: 32_000_000_000,
                signature: test_fixtures::seq::<96>(0x30),
            },
        };

        let json = serde_json::to_string(&deposit).expect("serialize");
        let roundtrip: Result<Deposit, _> = serde_json::from_str(json.as_str());
        assert!(roundtrip.is_err());
    }

    #[test]
    fn indexed_attestation_indices_json_are_strings() {
        let body = test_fixtures::phase0_beacon_block_body_fixture();
        let indexed = body.attester_slashings.0[0].attestation_1.clone();

        let json = serde_json::to_value(&indexed).expect("serialize indexed attestation");
        assert_eq!(json["attesting_indices"], serde_json::json!(["11", "12"]));

        let roundtrip: IndexedAttestation =
            serde_json::from_value(json).expect("deserialize indexed attestation");
        assert_eq!(roundtrip.attesting_indices.0, vec![11, 12]);
    }
}
