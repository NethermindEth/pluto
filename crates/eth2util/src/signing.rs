use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::PublicKey};
use pluto_eth2api::{
    ConsensusVersion, EthBeaconNodeApiClient, GetGenesisRequest, GetGenesisResponse,
    GetSpecRequest, GetSpecResponse,
    spec::phase0::{self, Domain, DomainType, Epoch, ForkData, Root, SigningData, Version},
    versioned::{SignedAggregateAndProofPayload, VersionedSignedAggregateAndProof},
};
use tree_hash::TreeHash;

/// Domain name as defined in the ETH2 spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainName {
    /// `DOMAIN_BEACON_PROPOSER`.
    BeaconProposer,
    /// `DOMAIN_BEACON_ATTESTER`.
    BeaconAttester,
    /// `DOMAIN_RANDAO`.
    Randao,
    /// `DOMAIN_VOLUNTARY_EXIT`.
    Exit,
    /// `DOMAIN_APPLICATION_BUILDER`.
    ApplicationBuilder,
    /// `DOMAIN_SELECTION_PROOF`.
    SelectionProof,
    /// `DOMAIN_AGGREGATE_AND_PROOF`.
    AggregateAndProof,
    /// `DOMAIN_SYNC_COMMITTEE`.
    SyncCommittee,
    /// `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF`.
    SyncCommitteeSelectionProof,
    /// `DOMAIN_CONTRIBUTION_AND_PROOF`.
    ContributionAndProof,
    /// `DOMAIN_DEPOSIT`.
    Deposit,
    /// `DOMAIN_BLOB_SIDECAR`.
    BlobSidecar,
}

impl DomainName {
    fn spec_name(self) -> &'static str {
        match self {
            Self::BeaconProposer => "DOMAIN_BEACON_PROPOSER",
            Self::BeaconAttester => "DOMAIN_BEACON_ATTESTER",
            Self::Randao => "DOMAIN_RANDAO",
            Self::Exit => "DOMAIN_VOLUNTARY_EXIT",
            Self::ApplicationBuilder => "DOMAIN_APPLICATION_BUILDER",
            Self::SelectionProof => "DOMAIN_SELECTION_PROOF",
            Self::AggregateAndProof => "DOMAIN_AGGREGATE_AND_PROOF",
            Self::SyncCommittee => "DOMAIN_SYNC_COMMITTEE",
            Self::SyncCommitteeSelectionProof => "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF",
            Self::ContributionAndProof => "DOMAIN_CONTRIBUTION_AND_PROOF",
            Self::Deposit => "DOMAIN_DEPOSIT",
            Self::BlobSidecar => "DOMAIN_BLOB_SIDECAR",
        }
    }
}

/// Signing error.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// Failed to fetch the beacon node spec.
    #[error("get spec: {0}")]
    GetSpec(String),

    /// The spec endpoint returned an unexpected response shape.
    #[error("unexpected spec response")]
    UnexpectedSpecResponse,

    /// Failed to fetch the beacon node genesis.
    #[error("get genesis: {0}")]
    GetGenesis(String),

    /// The genesis endpoint returned an unexpected response shape.
    #[error("unexpected genesis response")]
    UnexpectedGenesisResponse,

    /// Failed to fetch fork config.
    #[error("fetch fork config: {0}")]
    FetchForkConfig(String),

    /// The requested domain type was not found in the spec.
    #[error("domain type not found")]
    DomainTypeNotFound,

    /// The requested domain type could not be parsed.
    #[error("invalid domain type")]
    InvalidDomainType,

    /// The genesis fork version could not be parsed.
    #[error("invalid genesis fork version: {value}")]
    InvalidGenesisForkVersion {
        /// Raw genesis fork version value.
        value: String,
    },

    /// The genesis validators root could not be parsed.
    #[error("invalid genesis validators root: {value}")]
    InvalidGenesisValidatorsRoot {
        /// Raw genesis validators root value.
        value: String,
    },

    /// No matching Capella fork metadata exists for the genesis fork.
    #[error("compute domain: invalid fork hash: no capella fork for specified fork")]
    InvalidForkHash,

    /// The configured Capella fork version is malformed.
    #[error("compute domain: capella fork hash hex: {value}")]
    CapellaForkHashHex {
        /// Raw Capella fork version value.
        value: String,
    },

    /// No signature was provided.
    #[error("no signature found")]
    NoSignatureFound,

    /// Helper-layer error.
    #[error(transparent)]
    Helper(#[from] crate::helpers::HelperError),

    /// Network metadata error.
    #[error(transparent)]
    Network(#[from] crate::network::NetworkError),

    /// Cryptographic verification error.
    #[error(transparent)]
    Crypto(#[from] pluto_crypto::types::Error),
}

/// Result type for signing helpers.
pub type Result<T> = std::result::Result<T, SigningError>;

const ORDERED_FORKS: [ConsensusVersion; 6] = [
    ConsensusVersion::Altair,
    ConsensusVersion::Bellatrix,
    ConsensusVersion::Capella,
    ConsensusVersion::Deneb,
    ConsensusVersion::Electra,
    ConsensusVersion::Fulu,
];

/// Returns the beacon domain for the provided type.
pub async fn get_domain(
    client: &EthBeaconNodeApiClient,
    name: DomainName,
    epoch: Epoch,
) -> Result<Domain> {
    let spec = get_spec(client).await?;
    let domain_type = domain_type_from_spec(&spec, name)?;
    let (genesis_fork_version, genesis_validators_root) = get_genesis(client).await?;

    let domain = match name {
        DomainName::ApplicationBuilder => {
            compute_domain(domain_type, genesis_fork_version, Root::default())
        }
        DomainName::Exit => {
            let capella_version = capella_fork_version(genesis_fork_version)?;
            compute_domain(domain_type, capella_version, genesis_validators_root)
        }
        _ => {
            let current_version = active_fork_version(client, genesis_fork_version, epoch).await?;
            compute_domain(domain_type, current_version, genesis_validators_root)
        }
    };

    Ok(domain)
}

/// Wraps the signing root with the domain and returns the signed data root.
pub async fn get_data_root(
    client: &EthBeaconNodeApiClient,
    name: DomainName,
    epoch: Epoch,
    root: Root,
) -> Result<Root> {
    let domain = get_domain(client, name, epoch).await?;
    let msg = SigningData {
        object_root: root,
        domain,
    };

    Ok(msg.tree_hash_root().0)
}

/// Returns error if the signature does not match the eth2 signed
/// root.
pub async fn verify(
    client: &EthBeaconNodeApiClient,
    domain: DomainName,
    epoch: Epoch,
    sig_root: Root,
    signature: phase0::BLSSignature,
    pubkey: PublicKey,
) -> Result<()> {
    let sig_data = get_data_root(client, domain, epoch, sig_root).await?;

    if signature == [0; 96] {
        return Err(SigningError::NoSignatureFound);
    }

    BlstImpl.verify(&pubkey, &sig_data, &signature)?;
    Ok(())
}

/// Verifies the selection proof with the provided public
/// key.
pub async fn verify_aggregate_and_proof_selection(
    client: &EthBeaconNodeApiClient,
    pubkey: PublicKey,
    agg: &VersionedSignedAggregateAndProof,
) -> Result<()> {
    let slot = agg.aggregate_and_proof.data().slot;
    let epoch = crate::helpers::epoch_from_slot(client, slot).await?;
    let sig_root = slot.tree_hash_root().0;
    let selection_proof = selection_proof(agg);

    verify(
        client,
        DomainName::SelectionProof,
        epoch,
        sig_root,
        selection_proof,
        pubkey,
    )
    .await
}

fn selection_proof(agg: &VersionedSignedAggregateAndProof) -> phase0::BLSSignature {
    match &agg.aggregate_and_proof {
        SignedAggregateAndProofPayload::Phase0(payload)
        | SignedAggregateAndProofPayload::Altair(payload)
        | SignedAggregateAndProofPayload::Bellatrix(payload)
        | SignedAggregateAndProofPayload::Capella(payload)
        | SignedAggregateAndProofPayload::Deneb(payload) => payload.message.selection_proof,
        SignedAggregateAndProofPayload::Electra(payload)
        | SignedAggregateAndProofPayload::Fulu(payload) => payload.message.selection_proof,
    }
}

async fn get_spec(client: &EthBeaconNodeApiClient) -> Result<serde_json::Value> {
    let response = client
        .get_spec(GetSpecRequest {})
        .await
        .map_err(|err| SigningError::GetSpec(err.to_string()))?;

    match response {
        GetSpecResponse::Ok(spec) => Ok(spec.data),
        _ => Err(SigningError::UnexpectedSpecResponse),
    }
}

async fn get_genesis(client: &EthBeaconNodeApiClient) -> Result<(Version, Root)> {
    let response = client
        .get_genesis(GetGenesisRequest {})
        .await
        .map_err(|err| SigningError::GetGenesis(err.to_string()))?;

    let genesis = match response {
        GetGenesisResponse::Ok(genesis) => genesis.data,
        _ => return Err(SigningError::UnexpectedGenesisResponse),
    };

    let genesis_fork_version =
        parse_hex_array::<4>(&genesis.genesis_fork_version).ok_or_else(|| {
            SigningError::InvalidGenesisForkVersion {
                value: genesis.genesis_fork_version.clone(),
            }
        })?;
    let genesis_validators_root = parse_hex_array::<32>(&genesis.genesis_validators_root)
        .ok_or_else(|| SigningError::InvalidGenesisValidatorsRoot {
            value: genesis.genesis_validators_root.clone(),
        })?;

    Ok((genesis_fork_version, genesis_validators_root))
}

fn domain_type_from_spec(spec: &serde_json::Value, name: DomainName) -> Result<DomainType> {
    let domain_value = spec
        .as_object()
        .and_then(|map| map.get(name.spec_name()))
        .ok_or(SigningError::DomainTypeNotFound)?;

    let domain_hex = domain_value
        .as_str()
        .ok_or(SigningError::InvalidDomainType)?;

    parse_hex_array::<4>(domain_hex).ok_or(SigningError::InvalidDomainType)
}

async fn active_fork_version(
    client: &EthBeaconNodeApiClient,
    genesis_fork_version: Version,
    epoch: Epoch,
) -> Result<Version> {
    let fork_config = client
        .fetch_fork_config()
        .await
        .map_err(|err| SigningError::FetchForkConfig(err.to_string()))?;

    let mut current_version = genesis_fork_version;

    for fork in ORDERED_FORKS {
        if let Some(schedule) = fork_config.get(&fork)
            && schedule.epoch <= epoch
        {
            current_version = schedule.version;
        }
    }

    Ok(current_version)
}

fn capella_fork_version(genesis_fork_version: Version) -> Result<Version> {
    let genesis_hex = hex::encode(genesis_fork_version);
    let network = crate::network::supported_networks()?
        .into_iter()
        .find(|network| {
            network
                .genesis_fork_version_hex
                .trim_start_matches("0x")
                .eq_ignore_ascii_case(&genesis_hex)
        })
        .ok_or(SigningError::InvalidForkHash)?;

    parse_hex_array::<4>(network.capella_hard_fork).ok_or_else(|| {
        SigningError::CapellaForkHashHex {
            value: network.capella_hard_fork.to_string(),
        }
    })
}

fn compute_domain(
    domain_type: DomainType,
    current_version: Version,
    genesis_validators_root: Root,
) -> Domain {
    let fork_data = ForkData {
        current_version,
        genesis_validators_root,
    };
    let root = fork_data.tree_hash_root();

    let mut domain = Domain::default();
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&root.0[..28]);
    domain
}

fn parse_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(value.trim_start_matches("0x")).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_crypto::{tbls::Tbls, types::PrivateKey};
    use pluto_eth2api::v1::SignedValidatorRegistration;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const HOLESKY_GENESIS_FORK_VERSION: &str = "0x01017000";
    const HOLESKY_CAPELLA_FORK_VERSION: &str = "0x04017000";
    const GENESIS_VALIDATORS_ROOT: &str =
        "0x1111111111111111111111111111111111111111111111111111111111111111";

    #[tokio::test]
    async fn test_verify_registration_reference() {
        let server = MockServer::start().await;
        mount_spec(
            &server,
            spec_with_domain("DOMAIN_APPLICATION_BUILDER", "0x00000001"),
        )
        .await;
        mount_genesis(
            &server,
            genesis_response(HOLESKY_GENESIS_FORK_VERSION, GENESIS_VALIDATORS_ROOT),
        )
        .await;

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

        let reg: SignedValidatorRegistration =
            serde_json::from_str(registration_json).expect("deserialize reference registration");
        let sig_root = reg.message.tree_hash_root().0;

        let fork: Version = crate::network::network_to_fork_version_bytes("holesky")
            .expect("holesky fork version")
            .try_into()
            .expect("fork version length");
        let sig_data = crate::registration::get_message_signing_root(&reg.message, fork);

        let secret_share_bytes =
            hex::decode("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b")
                .expect("decode secret share");
        let secret_share: PrivateKey = secret_share_bytes
            .as_slice()
            .try_into()
            .expect("secret share length");

        let sig = BlstImpl
            .sign(&secret_share, &sig_data)
            .expect("sign reference payload");
        let sig_eth2 = phase0::BLSSignature::from(sig);

        assert_eq!(hex::encode(reg.signature), hex::encode(sig_eth2));

        let pubkey = BlstImpl
            .secret_to_public_key(&secret_share)
            .expect("derive public key");
        verify(
            &EthBeaconNodeApiClient::with_base_url(server.uri()).expect("client"),
            DomainName::ApplicationBuilder,
            0,
            sig_root,
            sig_eth2,
            pubkey,
        )
        .await
        .expect("verify builder signature");
    }

    #[tokio::test]
    async fn test_constant_application_builder() {
        let schedules = [
            vec![],
            vec![("ALTAIR", "0x02017000", "1")],
            vec![
                ("ALTAIR", "0x02017000", "1"),
                ("BELLATRIX", "0x03017000", "2"),
            ],
            vec![
                ("ALTAIR", "0x02017000", "1"),
                ("BELLATRIX", "0x03017000", "2"),
                ("DENEB", "0x05017000", "3"),
                ("ELECTRA", "0x06017000", "4"),
            ],
        ];

        for schedule in schedules {
            let server = MockServer::start().await;
            mount_spec(
                &server,
                spec_with_schedule("DOMAIN_APPLICATION_BUILDER", "0x00000001", &schedule),
            )
            .await;
            mount_genesis(
                &server,
                genesis_response(HOLESKY_GENESIS_FORK_VERSION, GENESIS_VALIDATORS_ROOT),
            )
            .await;

            let domain = get_domain(
                &EthBeaconNodeApiClient::with_base_url(server.uri()).expect("client"),
                DomainName::ApplicationBuilder,
                0,
            )
            .await
            .expect("builder domain");

            assert_eq!(
                hex::encode(domain),
                "000000015b83a23759c560b2d0c64576e1dcfc34ea94c4988f3e0d9f77f05387"
            );
        }
    }

    #[tokio::test]
    async fn domain_exit_uses_capella_domain() {
        let server = MockServer::start().await;
        mount_spec(
            &server,
            spec_with_schedule(
                "DOMAIN_VOLUNTARY_EXIT",
                "0x04000000",
                &[
                    ("ALTAIR", "0x02017000", "1"),
                    ("BELLATRIX", "0x03017000", "2"),
                    ("CAPELLA", HOLESKY_CAPELLA_FORK_VERSION, "3"),
                    ("DENEB", "0x05017000", "4"),
                    ("ELECTRA", "0x06017000", "5"),
                ],
            ),
        )
        .await;
        mount_genesis(
            &server,
            genesis_response(HOLESKY_GENESIS_FORK_VERSION, GENESIS_VALIDATORS_ROOT),
        )
        .await;

        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("client");
        let actual = get_domain(&client, DomainName::Exit, 100)
            .await
            .expect("exit domain");

        let expected = compute_domain(
            [0x04, 0x00, 0x00, 0x00],
            parse_hex_array(HOLESKY_CAPELLA_FORK_VERSION).expect("capella version"),
            parse_hex_array(GENESIS_VALIDATORS_ROOT).expect("genesis validators root"),
        );

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn missing_domain_type_returns_error() {
        let server = MockServer::start().await;
        mount_spec(&server, json!({ "data": {} })).await;

        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("client");
        let err = get_domain(&client, DomainName::ApplicationBuilder, 0)
            .await
            .expect_err("missing domain type should fail");

        assert!(matches!(err, SigningError::DomainTypeNotFound));
        assert_eq!(err.to_string(), "domain type not found");
    }

    #[tokio::test]
    async fn malformed_domain_type_returns_error() {
        let server = MockServer::start().await;
        mount_spec(
            &server,
            json!({ "data": { "DOMAIN_APPLICATION_BUILDER": "0x01" } }),
        )
        .await;

        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("client");
        let err = get_domain(&client, DomainName::ApplicationBuilder, 0)
            .await
            .expect_err("malformed domain type should fail");

        assert!(matches!(err, SigningError::InvalidDomainType));
        assert_eq!(err.to_string(), "invalid domain type");
    }

    #[tokio::test]
    async fn zero_signature_returns_error() {
        let server = MockServer::start().await;
        mount_spec(
            &server,
            spec_with_domain("DOMAIN_APPLICATION_BUILDER", "0x00000001"),
        )
        .await;
        mount_genesis(
            &server,
            genesis_response(HOLESKY_GENESIS_FORK_VERSION, GENESIS_VALIDATORS_ROOT),
        )
        .await;

        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("client");
        let err = verify(
            &client,
            DomainName::ApplicationBuilder,
            0,
            [0x22; 32],
            [0x00; 96],
            [0x33; 48],
        )
        .await
        .expect_err("zero signature should fail");

        assert!(matches!(err, SigningError::NoSignatureFound));
        assert_eq!(err.to_string(), "no signature found");
    }

    fn spec_with_domain(domain_key: &str, domain_value: &str) -> serde_json::Value {
        spec_with_schedule(domain_key, domain_value, &[])
    }

    fn spec_with_schedule(
        domain_key: &str,
        domain_value: &str,
        schedule: &[(&str, &str, &str)],
    ) -> serde_json::Value {
        let mut data = serde_json::Map::new();
        data.insert(domain_key.to_string(), json!(domain_value));

        for (fork_name, fork_version, fork_epoch) in schedule {
            data.insert(format!("{fork_name}_FORK_VERSION"), json!(fork_version));
            data.insert(format!("{fork_name}_FORK_EPOCH"), json!(fork_epoch));
        }

        for (fork_name, fork_version, fork_epoch) in [
            ("ALTAIR", "0x02000000", "74240"),
            ("BELLATRIX", "0x03000000", "144896"),
            ("CAPELLA", "0x04000000", "194048"),
            ("DENEB", "0x05000000", "269568"),
            ("ELECTRA", "0x06000000", "364032"),
            ("FULU", "0x07000000", "411392"),
        ] {
            data.entry(format!("{fork_name}_FORK_VERSION"))
                .or_insert_with(|| json!(fork_version));
            data.entry(format!("{fork_name}_FORK_EPOCH"))
                .or_insert_with(|| json!(fork_epoch));
        }

        json!({ "data": serde_json::Value::Object(data) })
    }

    fn genesis_response(
        genesis_fork_version: &str,
        genesis_validators_root: &str,
    ) -> serde_json::Value {
        json!({
            "data": {
                "genesis_fork_version": genesis_fork_version,
                "genesis_time": "1696000704",
                "genesis_validators_root": genesis_validators_root
            }
        })
    }

    async fn mount_spec(server: &MockServer, body: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    async fn mount_genesis(server: &MockServer, body: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }
}
