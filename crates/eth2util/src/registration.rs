use pluto_eth2api::{
    spec::{
        bellatrix::ExecutionAddress,
        phase0::{BLSPubKey, Domain, DomainType, ForkData, Root, SigningData, Version},
    },
    v1::ValidatorRegistration,
};
use tree_hash::TreeHash;

/// Default gas limit used in validator registration pre-generation.
pub const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

/// `DOMAIN_APPLICATION_BUILDER`.
/// See <https://github.com/ethereum/builder-specs/blob/7b269305e1e54f22ddb84b3da2f222e20adf6e4f/specs/bellatrix/builder.md#domain-types>.
const REGISTRATION_DOMAIN_TYPE: DomainType = [0x00, 0x00, 0x00, 0x01];

/// Registration error.
#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    /// Invalid fee recipient address.
    #[error("invalid fee recipient address: {0}")]
    InvalidAddress(#[from] crate::helpers::HelperError),
}

type Result<T> = std::result::Result<T, RegistrationError>;

/// Creates a new validator registration message.
pub fn new_message(
    pubkey: BLSPubKey,
    fee_recipient: &str,
    gas_limit: u64,
    timestamp: u64,
) -> Result<ValidatorRegistration> {
    let fee_recipient = execution_address_from_str(fee_recipient)?;

    Ok(ValidatorRegistration {
        fee_recipient,
        gas_limit,
        timestamp,
        pubkey,
    })
}

/// Parses and validates a `0x`-prefixed hex Ethereum address into `[u8; 20]`.
fn execution_address_from_str(addr: &str) -> Result<ExecutionAddress> {
    let address = crate::helpers::verify_address(addr)?;
    Ok(address.0.0)
}

/// Returns the validator registration signature domain.
/// `DOMAIN_APPLICATION_BUILDER` uses `GENESIS_FORK_VERSION` to compute domain.
/// Refer:
/// - https://github.com/ethereum/builder-specs/blob/100d4faf32e5dc672c963741769390ff09ab194a/specs/bellatrix/builder.md#signing
/// - https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#compute_domain
fn get_registration_domain(genesis_fork_version: Version) -> Domain {
    let fork_data = ForkData {
        current_version: genesis_fork_version,
        genesis_validators_root: Root::default(), /* GenesisValidatorsRoot is zero for validator
                                                   * registration. */
    };

    let fork_data_root = fork_data.tree_hash_root();

    let mut domain = Domain::default();
    domain[0..4].copy_from_slice(&REGISTRATION_DOMAIN_TYPE);
    domain[4..].copy_from_slice(&fork_data_root.0[..28]);

    domain
}

/// Returns the validator registration message signing root.
pub fn get_message_signing_root(
    msg: &ValidatorRegistration,
    genesis_fork_version: Version,
) -> Root {
    let msg_root = msg.tree_hash_root();
    let domain = get_registration_domain(genesis_fork_version);

    let signing_data = SigningData {
        object_root: msg_root.0,
        domain,
    };

    signing_data.tree_hash_root().0
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls};

    #[test]
    fn new_message_works() {
        let pubkey = [0xABu8; 48];
        let fee_recipient = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";
        let gas_limit = 30_000_000u64;
        // Jan 1, 2000 00:00:00 UTC in unix seconds
        let timestamp = 946_684_800u64;

        let result = new_message(pubkey, fee_recipient, gas_limit, timestamp).unwrap();

        assert_eq!(result.pubkey, pubkey);
        assert_eq!(result.gas_limit, gas_limit);
        assert_eq!(result.timestamp, timestamp);
        assert_eq!(
            result.fee_recipient,
            [
                50, 29, 203, 82, 159, 57, 69, 188, 148, 254, 206, 169, 211, 188, 92, 175, 53, 37,
                59, 148,
            ]
        );
    }

    #[test]
    fn new_message_bad_address() {
        let pubkey = [0xABu8; 48];
        // Truncated address (39 hex chars instead of 40)
        let fee_recipient = "0x321dcb529f3945bc94fecea9d3bc5caf35253b9";
        let gas_limit = 30_000_000u64;
        let timestamp = 946_684_800u64;

        let result = new_message(pubkey, fee_recipient, gas_limit, timestamp);
        assert!(matches!(
            result,
            Err(RegistrationError::InvalidAddress(
                crate::helpers::HelperError::InvalidAddress(_)
            ))
        ));
    }

    #[test]
    fn get_message_signing_root_works() {
        let pubkey = [0xABu8; 48];
        let fee_recipient: ExecutionAddress = [
            50, 29, 203, 82, 159, 57, 69, 188, 148, 254, 206, 169, 211, 188, 92, 175, 53, 37, 59,
            148,
        ];

        let msg = ValidatorRegistration {
            fee_recipient,
            gas_limit: 30_000_000,
            timestamp: 946_684_800,
            pubkey,
        };

        let fork_version_bytes = crate::network::network_to_fork_version_bytes("goerli").unwrap();
        let fork_version: Version = fork_version_bytes.as_slice().try_into().unwrap();

        let result = get_message_signing_root(&msg, fork_version);

        let expected_root =
            hex::decode("a71f91bf1e595fc8d1bb7f33ad7f4a0c228512ec3dbf780302304dc61621b78b")
                .unwrap();
        assert_eq!(result, expected_root.as_slice());
    }

    #[test]
    fn verify_signed_registration() {
        // Test data obtained from teku.
        let sk_bytes =
            hex::decode("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b")
                .unwrap();
        let secret: pluto_crypto::types::PrivateKey = sk_bytes.as_slice().try_into().unwrap();

        let pubkey = BlstImpl.secret_to_public_key(&secret).unwrap();

        let registration_json = r#"
			{
			  "message": {
				"fee_recipient": "0x000000000000000000000000000000000000dEaD",
				"gas_limit": "30000000",
				"timestamp": "1646092800",
				"pubkey": "0x86966350b672bd502bfbdb37a6ea8a7392e8fb7f5ebb5c5e2055f4ee168ebfab0fef63084f28c9f62c3ba71f825e527e"
			  },
			  "signature": "0xad393c5b42b382cf93cd14f302b0175b4f9ccb000c201d42c3a6389971b8d910a81333d55ad2944b836a9bb35ba968ab06635dcd706380516ad0c653f48b1c6d52b8771c78d708e943b3ea8da59392fbf909decde262adc944fe3e57120d9bb4"
			}"#;
        let registration: serde_json::Value = serde_json::from_str(registration_json).unwrap();
        let message = registration["message"].as_object().unwrap();

        let fee_recipient: ExecutionAddress = hex::decode(
            message["fee_recipient"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
        let reg_pubkey: BLSPubKey =
            hex::decode(message["pubkey"].as_str().unwrap().trim_start_matches("0x"))
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let gas_limit = message["gas_limit"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let timestamp = message["timestamp"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();

        let msg = ValidatorRegistration {
            fee_recipient,
            gas_limit,
            timestamp,
            pubkey: reg_pubkey,
        };

        let fork_version_bytes = crate::network::network_to_fork_version_bytes("holesky").unwrap();
        let fork_version: Version = fork_version_bytes.as_slice().try_into().unwrap();

        let signing_root = get_message_signing_root(&msg, fork_version);

        let expected_root =
            hex::decode("fc657efa54a1e050289ddc5a72fbb76c778ac383a3c73309082e01f132ba23a8")
                .unwrap();
        assert_eq!(signing_root, expected_root.as_slice());

        let signature: pluto_crypto::types::Signature = hex::decode(
            registration["signature"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();

        BlstImpl
            .verify(&pubkey, &signing_root, &signature)
            .expect("BLS signature verification failed");
    }
}
