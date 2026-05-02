use pluto_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    types::{PublicKey, Signature},
};
use pluto_eth2api::{
    EthBeaconNodeApiClient, EthBeaconNodeApiClientError,
    spec::phase0::{Domain, Epoch, Root, SigningData},
    versioned::VersionedSignedAggregateAndProof,
};
use tree_hash::TreeHash;

/// Domain name as defined in the consensus and builder specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainName {
    /// `DOMAIN_BEACON_PROPOSER`
    BeaconProposer,
    /// `DOMAIN_BEACON_ATTESTER`
    BeaconAttester,
    /// `DOMAIN_RANDAO`
    Randao,
    /// `DOMAIN_VOLUNTARY_EXIT`
    VoluntaryExit,
    /// `DOMAIN_APPLICATION_BUILDER`
    ApplicationBuilder,
    /// `DOMAIN_SELECTION_PROOF`
    SelectionProof,
    /// `DOMAIN_AGGREGATE_AND_PROOF`
    AggregateAndProof,
    /// `DOMAIN_SYNC_COMMITTEE`
    SyncCommittee,
    /// `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF`
    SyncCommitteeSelectionProof,
    /// `DOMAIN_CONTRIBUTION_AND_PROOF`
    ContributionAndProof,
    /// `DOMAIN_DEPOSIT`
    Deposit,
    /// `DOMAIN_BLOB_SIDECAR`
    BlobSidecar,
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_spec_key())
    }
}

impl DomainName {
    /// Returns the spec key used in `/eth/v1/config/spec`.
    pub const fn as_spec_key(self) -> &'static str {
        match self {
            Self::BeaconProposer => "DOMAIN_BEACON_PROPOSER",
            Self::BeaconAttester => "DOMAIN_BEACON_ATTESTER",
            Self::Randao => "DOMAIN_RANDAO",
            Self::VoluntaryExit => "DOMAIN_VOLUNTARY_EXIT",
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
    /// Beacon-node domain lookup failed.
    #[error(transparent)]
    BeaconNode(#[from] EthBeaconNodeApiClientError),

    /// Slot/epoch helper failed.
    #[error(transparent)]
    Helper(#[from] crate::helpers::HelperError),

    /// Aggregate-and-proof version is unsupported.
    #[error("unknown aggregate-and-proof version")]
    UnknownAggregateAndProofVersion,

    /// Zero signature rejected before attempting BLS verification.
    #[error("no signature found")]
    ZeroSignature,

    /// Underlying BLS verification error.
    #[error(transparent)]
    Verification(#[from] pluto_crypto::types::Error),
}

type Result<T> = std::result::Result<T, SigningError>;

/// Computes the eth2 signing root for a message root and domain.
pub(crate) fn compute_signing_root(message_root: Root, domain: Domain) -> Root {
    SigningData {
        object_root: message_root,
        domain,
    }
    .tree_hash_root()
    .0
}

/// Returns the beacon domain for the provided type.
pub async fn get_domain(
    client: &EthBeaconNodeApiClient,
    name: DomainName,
    epoch: Epoch,
) -> Result<Domain> {
    let domain_type = client.fetch_domain_type(name.as_spec_key()).await?;

    if name == DomainName::ApplicationBuilder {
        return Ok(client.fetch_genesis_domain(domain_type).await?);
    }

    Ok(client.fetch_domain(domain_type, epoch).await?)
}

/// Wraps the message root with the resolved domain and returns the signing-data
/// root.
pub async fn get_data_root(
    client: &EthBeaconNodeApiClient,
    name: DomainName,
    epoch: Epoch,
    root: Root,
) -> Result<Root> {
    Ok(compute_signing_root(
        root,
        get_domain(client, name, epoch).await?,
    ))
}

/// Verifies a signature against the resolved eth2 domain signing root.
pub async fn verify(
    client: &EthBeaconNodeApiClient,
    domain_name: DomainName,
    epoch: Epoch,
    message_root: Root,
    signature: &Signature,
    pubkey: &PublicKey,
) -> Result<()> {
    if *signature == [0; 96] {
        return Err(SigningError::ZeroSignature);
    }

    let signing_root = get_data_root(client, domain_name, epoch, message_root).await?;

    BlstImpl.verify(pubkey, &signing_root, signature)?;

    Ok(())
}

/// Verifies the selection proof embedded in an aggregate-and-proof payload.
pub async fn verify_aggregate_and_proof_selection(
    client: &EthBeaconNodeApiClient,
    pubkey: &PublicKey,
    agg: &VersionedSignedAggregateAndProof,
) -> Result<()> {
    let slot = agg
        .slot()
        .ok_or(SigningError::UnknownAggregateAndProofVersion)?;
    let epoch = crate::helpers::epoch_from_slot(client, slot).await?;
    let message_root = slot.tree_hash_root().0;
    let selection_proof = agg
        .selection_proof()
        .ok_or(SigningError::UnknownAggregateAndProofVersion)?;

    verify(
        client,
        DomainName::SelectionProof,
        epoch,
        message_root,
        &selection_proof,
        pubkey,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_crypto::tbls::Tbls;
    use pluto_eth2api::{
        compute_builder_domain, compute_domain,
        spec::{bellatrix::ExecutionAddress, phase0::Version},
        v1::ValidatorRegistration,
    };
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const BUILDER_DOMAIN_TYPE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

    fn secret_key(hex_value: &str) -> pluto_crypto::types::PrivateKey {
        let bytes = hex::decode(hex_value).unwrap();
        bytes.as_slice().try_into().unwrap()
    }

    fn spec_fixture() -> serde_json::Value {
        json!({
            "DOMAIN_BEACON_PROPOSER": "0x00000000",
            "DOMAIN_VOLUNTARY_EXIT": "0x04000000",
            "DOMAIN_APPLICATION_BUILDER": "0x00000001",
            "ALTAIR_FORK_VERSION": "0x01020304",
            "ALTAIR_FORK_EPOCH": "10",
            "BELLATRIX_FORK_VERSION": "0x02030405",
            "BELLATRIX_FORK_EPOCH": "20",
            "CAPELLA_FORK_VERSION": "0x03040506",
            "CAPELLA_FORK_EPOCH": "30",
            "DENEB_FORK_VERSION": "0x04050607",
            "DENEB_FORK_EPOCH": "40",
            "ELECTRA_FORK_VERSION": "0x05060708",
            "ELECTRA_FORK_EPOCH": "50",
            "FULU_FORK_VERSION": "0x06070809",
            "FULU_FORK_EPOCH": "60"
        })
    }

    async fn mock_beacon_client() -> (MockServer, EthBeaconNodeApiClient) {
        let server = MockServer::start().await;
        let base_url = server.uri();

        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": spec_fixture(),
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "genesis_time": "0",
                    "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "genesis_fork_version": "0x01017000",
                }
            })))
            .mount(&server)
            .await;

        (
            server,
            EthBeaconNodeApiClient::with_base_url(base_url).unwrap(),
        )
    }

    #[test]
    fn compute_signing_root_matches_registration_vector() {
        let fee_recipient: ExecutionAddress =
            hex::decode("000000000000000000000000000000000000dead")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let pubkey = hex::decode(
            "86966350b672bd502bfbdb37a6ea8a7392e8fb7f5ebb5c5e2055f4ee168ebfab0fef63084f28c9f62c3ba71f825e527e",
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
        let message = ValidatorRegistration {
            fee_recipient,
            gas_limit: 30_000_000,
            timestamp: 1_646_092_800,
            pubkey,
        };
        let genesis_fork_version: Version = [0x01, 0x01, 0x70, 0x00];
        let domain = compute_builder_domain(BUILDER_DOMAIN_TYPE, genesis_fork_version);

        let signing_root = compute_signing_root(message.message_root(), domain);

        assert_eq!(
            hex::encode(signing_root),
            "fc657efa54a1e050289ddc5a72fbb76c778ac383a3c73309082e01f132ba23a8"
        );
    }

    #[tokio::test]
    async fn get_domain_matches_builder_vector() {
        let (_server, client) = mock_beacon_client().await;

        let domain = get_domain(&client, DomainName::ApplicationBuilder, 1_000)
            .await
            .unwrap();

        assert_eq!(
            hex::encode(domain),
            "000000015b83a23759c560b2d0c64576e1dcfc34ea94c4988f3e0d9f77f05387"
        );
    }

    #[tokio::test]
    async fn get_domain_uses_capella_for_voluntary_exit() {
        let (_server, client) = mock_beacon_client().await;

        let domain = get_domain(&client, DomainName::VoluntaryExit, 1_000)
            .await
            .unwrap();

        assert_eq!(
            domain,
            compute_domain([0x04, 0x00, 0x00, 0x00], [0x03, 0x04, 0x05, 0x06], [0; 32])
        );
    }

    #[tokio::test]
    async fn get_data_root_matches_registration_vector() {
        let (_server, client) = mock_beacon_client().await;

        let fee_recipient: ExecutionAddress =
            hex::decode("000000000000000000000000000000000000dead")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let pubkey = hex::decode(
            "86966350b672bd502bfbdb37a6ea8a7392e8fb7f5ebb5c5e2055f4ee168ebfab0fef63084f28c9f62c3ba71f825e527e",
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
        let message = ValidatorRegistration {
            fee_recipient,
            gas_limit: 30_000_000,
            timestamp: 1_646_092_800,
            pubkey,
        };

        let signing_root = get_data_root(
            &client,
            DomainName::ApplicationBuilder,
            0,
            message.message_root(),
        )
        .await
        .unwrap();

        assert_eq!(
            hex::encode(signing_root),
            "fc657efa54a1e050289ddc5a72fbb76c778ac383a3c73309082e01f132ba23a8"
        );
    }

    #[tokio::test]
    async fn verify_accepts_valid_signature() {
        let (_server, client) = mock_beacon_client().await;

        let secret = secret_key("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b");
        let pubkey = BlstImpl.secret_to_public_key(&secret).unwrap();
        let fee_recipient: ExecutionAddress =
            hex::decode("000000000000000000000000000000000000dead")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let message = ValidatorRegistration {
            fee_recipient,
            gas_limit: 30_000_000,
            timestamp: 1_646_092_800,
            pubkey,
        };
        let message_root = message.message_root();
        let signing_root = get_data_root(&client, DomainName::ApplicationBuilder, 0, message_root)
            .await
            .unwrap();
        let signature = BlstImpl.sign(&secret, &signing_root).unwrap();

        verify(
            &client,
            DomainName::ApplicationBuilder,
            0,
            message_root,
            &signature,
            &pubkey,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn verify_rejects_zero_signature() {
        let (_server, client) = mock_beacon_client().await;
        let pubkey = [0x11; 48];
        let err = verify(
            &client,
            DomainName::ApplicationBuilder,
            0,
            [0x22; 32],
            &[0; 96],
            &pubkey,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, SigningError::ZeroSignature));
    }

    #[tokio::test]
    async fn verify_rejects_wrong_pubkey() {
        let (_server, client) = mock_beacon_client().await;

        let secret = secret_key("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b");
        let wrong_secret =
            secret_key("01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d");
        let pubkey = BlstImpl.secret_to_public_key(&wrong_secret).unwrap();
        let message_root = [0x55; 32];
        let signing_root = get_data_root(&client, DomainName::ApplicationBuilder, 0, message_root)
            .await
            .unwrap();
        let signature = BlstImpl.sign(&secret, &signing_root).unwrap();

        let err = verify(
            &client,
            DomainName::ApplicationBuilder,
            0,
            message_root,
            &signature,
            &pubkey,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, SigningError::Verification(_)));
    }

    #[tokio::test]
    async fn verify_rejects_wrong_message_root() {
        let (_server, client) = mock_beacon_client().await;

        let secret = secret_key("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b");
        let pubkey = BlstImpl.secret_to_public_key(&secret).unwrap();
        let signed_message_root = [0x55; 32];
        let verified_message_root = [0x66; 32];
        let signing_root = get_data_root(
            &client,
            DomainName::ApplicationBuilder,
            0,
            signed_message_root,
        )
        .await
        .unwrap();
        let signature = BlstImpl.sign(&secret, &signing_root).unwrap();

        let err = verify(
            &client,
            DomainName::ApplicationBuilder,
            0,
            verified_message_root,
            &signature,
            &pubkey,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, SigningError::Verification(_)));
    }
}
