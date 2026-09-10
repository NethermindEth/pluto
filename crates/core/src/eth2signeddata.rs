//! Eth2 signed-data verification.
//!
//! Extends [`SignedData`] variants that carry beacon-chain signatures with the
//! metadata needed to verify them: the signing `DomainName` and the signing
//! `Epoch`. `verify_eth2_signed_data` ties the two together with the
//! upstream beacon-node domain lookup and BLS verification.

use pluto_crypto::types::PublicKey;
use pluto_eth2api::{client::EthBeaconNodeApiClient, spec::phase0::Epoch};
use pluto_eth2util::{
    helpers::{self, HelperError},
    signing::{self, DomainName, SigningError},
};
use pluto_ssz::HashRoot;

use crate::{
    signeddata::{
        Attestation, BeaconCommitteeSelection, SignedAggregateAndProof, SignedDataError,
        SignedRandao, SignedSyncContributionAndProof, SignedSyncMessage, SignedVoluntaryExit,
        SyncCommitteeSelection, SyncContributionAndProof, VersionedAttestation,
        VersionedSignedAggregateAndProof, VersionedSignedProposal,
        VersionedSignedValidatorRegistration,
    },
    types::{Signature, SignedData},
};

/// Error returned while resolving the signing epoch for, or verifying, an
/// [`Eth2SignedData`].
#[derive(Debug, thiserror::Error)]
pub enum Eth2SignedDataError {
    /// Failure while extracting the message root or epoch from the payload.
    #[error(transparent)]
    SignedData(#[from] SignedDataError),

    /// Beacon-node domain lookup or BLS verification failed.
    #[error(transparent)]
    Signing(#[from] SigningError),

    /// Slot-to-epoch conversion failed.
    #[error(transparent)]
    Helper(#[from] HelperError),
}

/// A [`SignedData`] payload that carries an eth2 beacon-chain signature —
/// the enum equivalent of Go's `core.Eth2SignedData` interface.
///
/// Obtained from [`SignedData::as_eth2_signed_data`], the port of Go's
/// `data.(core.Eth2SignedData)` type assertion, so the variants below are
/// exactly the payloads with a beacon-chain signing domain.
///
/// The signing root is the payload's [`Self::message_root`] wrapped with the
/// domain identified by [`Self::domain_name`] at the epoch returned by
/// [`Self::epoch`].
#[derive(Debug, Clone, Copy)]
pub enum Eth2SignedData<'a> {
    /// Signed beacon block proposal.
    VersionedSignedProposal(&'a VersionedSignedProposal),
    /// Non-versioned (phase0) attestation.
    Attestation(&'a Attestation),
    /// Versioned attestation.
    VersionedAttestation(&'a VersionedAttestation),
    /// Signed voluntary exit.
    SignedVoluntaryExit(&'a SignedVoluntaryExit),
    /// Signed validator registration.
    VersionedSignedValidatorRegistration(&'a VersionedSignedValidatorRegistration),
    /// Signed randao reveal.
    SignedRandao(&'a SignedRandao),
    /// Beacon committee selection proof.
    BeaconCommitteeSelection(&'a BeaconCommitteeSelection),
    /// Non-versioned (phase0) signed aggregate-and-proof.
    SignedAggregateAndProof(&'a SignedAggregateAndProof),
    /// Versioned signed aggregate-and-proof.
    VersionedSignedAggregateAndProof(&'a VersionedSignedAggregateAndProof),
    /// Signed sync committee message.
    SignedSyncMessage(&'a SignedSyncMessage),
    /// Signed sync contribution-and-proof.
    SignedSyncContributionAndProof(&'a SignedSyncContributionAndProof),
    /// Sync committee selection proof.
    SyncCommitteeSelection(&'a SyncCommitteeSelection),
    /// Sync contribution-and-proof (signed over its selection proof).
    SyncContributionAndProof(&'a SyncContributionAndProof),
}

impl Eth2SignedData<'_> {
    /// Returns the eth2 signing domain for this data.
    pub fn domain_name(&self) -> DomainName {
        match self {
            Self::VersionedSignedProposal(_) => DomainName::BeaconProposer,
            Self::Attestation(_) | Self::VersionedAttestation(_) => DomainName::BeaconAttester,
            Self::SignedVoluntaryExit(_) => DomainName::VoluntaryExit,
            Self::VersionedSignedValidatorRegistration(_) => DomainName::ApplicationBuilder,
            Self::SignedRandao(_) => DomainName::Randao,
            Self::BeaconCommitteeSelection(_) => DomainName::SelectionProof,
            Self::SignedAggregateAndProof(_) | Self::VersionedSignedAggregateAndProof(_) => {
                DomainName::AggregateAndProof
            }
            Self::SignedSyncMessage(_) => DomainName::SyncCommittee,
            Self::SignedSyncContributionAndProof(_) => DomainName::ContributionAndProof,
            Self::SyncCommitteeSelection(_) | Self::SyncContributionAndProof(_) => {
                DomainName::SyncCommitteeSelectionProof
            }
        }
    }

    /// Returns the epoch at which the signing domain is resolved.
    pub async fn epoch(
        &self,
        client: &EthBeaconNodeApiClient,
    ) -> Result<Epoch, Eth2SignedDataError> {
        match self {
            Self::VersionedSignedProposal(data) => {
                if data.0.version == pluto_eth2api::versioned::DataVersion::Unknown {
                    return Err(SignedDataError::UnknownVersion.into());
                }

                Ok(helpers::epoch_from_slot(client, data.0.block.slot()).await?)
            }
            Self::Attestation(data) => Ok(data.0.data.target.epoch),
            Self::VersionedAttestation(data) => {
                let version = data.0.version;
                if version == pluto_eth2api::versioned::DataVersion::Unknown {
                    return Err(SignedDataError::UnknownVersion.into());
                }

                let inner = data
                    .0
                    .attestation
                    .as_ref()
                    .ok_or(SignedDataError::MissingAttestation(version))?
                    .data();

                Ok(inner.target.epoch)
            }
            Self::SignedVoluntaryExit(data) => Ok(data.0.message.epoch),
            // Always use epoch 0 for DomainApplicationBuilder.
            Self::VersionedSignedValidatorRegistration(_) => Ok(0),
            Self::SignedRandao(data) => Ok(data.0.epoch),
            Self::BeaconCommitteeSelection(data) => {
                Ok(helpers::epoch_from_slot(client, data.0.slot).await?)
            }
            Self::SignedAggregateAndProof(data) => {
                Ok(helpers::epoch_from_slot(client, data.0.message.aggregate.data.slot).await?)
            }
            Self::VersionedSignedAggregateAndProof(data) => {
                let slot = data.0.slot().ok_or(SignedDataError::UnknownVersion)?;

                Ok(helpers::epoch_from_slot(client, slot).await?)
            }
            Self::SignedSyncMessage(data) => {
                Ok(helpers::epoch_from_slot(client, data.0.slot).await?)
            }
            Self::SignedSyncContributionAndProof(data) => {
                Ok(helpers::epoch_from_slot(client, data.0.message.contribution.slot).await?)
            }
            Self::SyncCommitteeSelection(data) => {
                Ok(helpers::epoch_from_slot(client, data.0.slot).await?)
            }
            Self::SyncContributionAndProof(data) => {
                Ok(helpers::epoch_from_slot(client, data.0.contribution.slot).await?)
            }
        }
    }

    /// Returns the payload's BLS signature.
    pub fn signature(&self) -> Result<Signature, SignedDataError> {
        match self {
            Self::VersionedSignedProposal(data) => data.signature(),
            Self::Attestation(data) => data.signature(),
            Self::VersionedAttestation(data) => data.signature(),
            Self::SignedVoluntaryExit(data) => data.signature(),
            Self::VersionedSignedValidatorRegistration(data) => data.signature(),
            Self::SignedRandao(data) => data.signature(),
            Self::BeaconCommitteeSelection(data) => data.signature(),
            Self::SignedAggregateAndProof(data) => data.signature(),
            Self::VersionedSignedAggregateAndProof(data) => data.signature(),
            Self::SignedSyncMessage(data) => data.signature(),
            Self::SignedSyncContributionAndProof(data) => data.signature(),
            Self::SyncCommitteeSelection(data) => data.signature(),
            Self::SyncContributionAndProof(data) => data.signature(),
        }
    }

    /// Returns the hash-tree-root of the signed message.
    pub fn message_root(&self) -> Result<HashRoot, SignedDataError> {
        match self {
            Self::VersionedSignedProposal(data) => data.message_root(),
            Self::Attestation(data) => data.message_root(),
            Self::VersionedAttestation(data) => data.message_root(),
            Self::SignedVoluntaryExit(data) => data.message_root(),
            Self::VersionedSignedValidatorRegistration(data) => data.message_root(),
            Self::SignedRandao(data) => data.message_root(),
            Self::BeaconCommitteeSelection(data) => data.message_root(),
            Self::SignedAggregateAndProof(data) => data.message_root(),
            Self::VersionedSignedAggregateAndProof(data) => data.message_root(),
            Self::SignedSyncMessage(data) => data.message_root(),
            Self::SignedSyncContributionAndProof(data) => data.message_root(),
            Self::SyncCommitteeSelection(data) => data.message_root(),
            Self::SyncContributionAndProof(data) => data.message_root(),
        }
    }
}

impl SignedData {
    /// Views this payload as an [`Eth2SignedData`], mirroring Go's
    /// `data.(core.Eth2SignedData)` type assertion. Returns `None` for
    /// variants without a beacon-chain signing domain (e.g. a raw
    /// [`Signature`]).
    pub fn as_eth2_signed_data(&self) -> Option<Eth2SignedData<'_>> {
        Some(match self {
            Self::Signature(_) => return None,
            Self::VersionedSignedProposal(data) => Eth2SignedData::VersionedSignedProposal(data),
            Self::Attestation(data) => Eth2SignedData::Attestation(data),
            Self::VersionedAttestation(data) => Eth2SignedData::VersionedAttestation(data),
            Self::SignedVoluntaryExit(data) => Eth2SignedData::SignedVoluntaryExit(data),
            Self::VersionedSignedValidatorRegistration(data) => {
                Eth2SignedData::VersionedSignedValidatorRegistration(data)
            }
            Self::SignedRandao(data) => Eth2SignedData::SignedRandao(data),
            Self::BeaconCommitteeSelection(data) => Eth2SignedData::BeaconCommitteeSelection(data),
            Self::SyncCommitteeSelection(data) => Eth2SignedData::SyncCommitteeSelection(data),
            Self::SignedAggregateAndProof(data) => Eth2SignedData::SignedAggregateAndProof(data),
            Self::VersionedSignedAggregateAndProof(data) => {
                Eth2SignedData::VersionedSignedAggregateAndProof(data)
            }
            Self::SignedSyncMessage(data) => Eth2SignedData::SignedSyncMessage(data),
            Self::SignedSyncContributionAndProof(data) => {
                Eth2SignedData::SignedSyncContributionAndProof(data)
            }
            // Go's `SyncContributionAndProof` also carries `DomainName`/
            // `Epoch` (`charon/core/signeddata.go`), so its type assertion
            // succeeds there too.
            Self::SyncContributionAndProof(data) => Eth2SignedData::SyncContributionAndProof(data),
            #[cfg(test)]
            Self::Mock(_) => return None,
        })
    }
}

/// Verifies the eth2 signature associated with the given [`Eth2SignedData`].
pub async fn verify_eth2_signed_data(
    client: &EthBeaconNodeApiClient,
    data: Eth2SignedData<'_>,
    pubkey: &PublicKey,
) -> Result<(), Eth2SignedDataError> {
    let sig_root = data.message_root()?;
    let signature = data.signature()?;
    let epoch = data.epoch(client).await?;

    signing::verify(
        client,
        data.domain_name(),
        epoch,
        sig_root,
        &signature,
        pubkey,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use pluto_crypto::tbls;
    use pluto_eth2api::spec::phase0;
    use pluto_testutil::BeaconMock;
    use serde::de::DeserializeOwned;

    use super::*;
    use crate::types::{SIGNATURE_LENGTH, Signature};

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("signeddata")
            .join(name)
    }

    fn load<T: DeserializeOwned>(name: &str) -> T {
        let json = fs::read_to_string(fixture_path(name)).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    /// The non-versioned `Attestation`/`SignedAggregateAndProof` wrappers have
    /// no golden JSON fixture, so build a phase0 sample by hand.
    fn sample_attestation_data() -> phase0::AttestationData {
        phase0::AttestationData {
            slot: 1,
            index: 2,
            beacon_block_root: [0x11; 32],
            source: phase0::Checkpoint {
                epoch: 3,
                root: [0x22; 32],
            },
            target: phase0::Checkpoint {
                epoch: 4,
                root: [0x33; 32],
            },
        }
    }

    fn sample_phase0_attestation() -> phase0::Attestation {
        phase0::Attestation {
            aggregation_bits: serde_json::from_str("\"0x0101\"").unwrap(),
            data: sample_attestation_data(),
            signature: [0x34; 96],
        }
    }

    /// Mirrors Go's `TestVerifyEth2SignedData`: resolve the epoch and message
    /// root, BLS-sign the signing-domain data root, inject the signature, and
    /// assert verification succeeds.
    async fn assert_verifies(client: &EthBeaconNodeApiClient, data: impl Into<SignedData>) {
        let data: SignedData = data.into();
        let eth2 = data.as_eth2_signed_data().expect("eth2 signed data");
        let epoch = eth2.epoch(client).await.unwrap();
        let root = eth2.message_root().unwrap();

        let mut rng = rand::thread_rng();
        let secret = tbls::generate_secret_key(&mut rng).unwrap();
        let pubkey = tbls::secret_to_public_key(&secret).unwrap();

        let sig_data = signing::get_data_root(client, eth2.domain_name(), epoch, root)
            .await
            .unwrap();
        let sig: Signature = tbls::sign(&secret, &sig_data).unwrap();

        let signed = data.set_signature(sig).unwrap();

        verify_eth2_signed_data(
            client,
            signed.as_eth2_signed_data().expect("eth2 signed data"),
            &pubkey,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn verify_beacon_block() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data: VersionedSignedProposal =
            load("TestJSONSerialisation_VersionedSignedProposal.json.golden");
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_attestation() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data: VersionedAttestation =
            load("TestJSONSerialisation_VersionedAttestation.json.golden");
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_randao() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data: SignedRandao = load("TestJSONSerialisation_SignedRandao.json.golden");
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_voluntary_exit() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data: SignedVoluntaryExit =
            load("TestJSONSerialisation_SignedVoluntaryExit.json.golden");
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_registration() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data: VersionedSignedValidatorRegistration =
            load("VersionedSignedValidatorRegistration.v1.json");
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_beacon_committee_selection() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data: BeaconCommitteeSelection =
            load("TestJSONSerialisation_BeaconCommitteeSelection.json.golden");
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_aggregate_and_proof() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data: VersionedSignedAggregateAndProof =
            load("TestJSONSerialisation_VersionedSignedAggregateAndProof.json.golden");
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_phase0_attestation() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data = Attestation::new(sample_phase0_attestation());
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_phase0_aggregate_and_proof() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data = SignedAggregateAndProof::new(phase0::SignedAggregateAndProof {
            message: phase0::AggregateAndProof {
                aggregator_index: 7,
                aggregate: sample_phase0_attestation(),
                selection_proof: [0x55; 96],
            },
            signature: [0x66; 96],
        });
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_sync_committee_message() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data: SignedSyncMessage = load("TestJSONSerialisation_SignedSyncMessage.json.golden");
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_sync_contribution_and_proof() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data: SignedSyncContributionAndProof =
            load("TestJSONSerialisation_SignedSyncContributionAndProof.json.golden");
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_sync_committee_selection() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let data: SyncCommitteeSelection =
            load("TestJSONSerialisation_SyncCommitteeSelection.json.golden");
        assert_verifies(mock.client(), data).await;
    }

    #[tokio::test]
    async fn verify_rejects_wrong_pubkey() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let client = mock.client();
        let data: SignedData =
            load::<SignedRandao>("TestJSONSerialisation_SignedRandao.json.golden").into();
        let eth2 = data.as_eth2_signed_data().unwrap();

        let epoch = eth2.epoch(client).await.unwrap();
        let root = eth2.message_root().unwrap();

        let mut rng = rand::thread_rng();
        let secret = tbls::generate_secret_key(&mut rng).unwrap();
        let wrong_secret = tbls::generate_secret_key(&mut rng).unwrap();
        let wrong_pubkey = tbls::secret_to_public_key(&wrong_secret).unwrap();

        let sig_data = signing::get_data_root(client, eth2.domain_name(), epoch, root)
            .await
            .unwrap();
        let sig: Signature = tbls::sign(&secret, &sig_data).unwrap();
        let signed = data.set_signature(sig).unwrap();

        let err =
            verify_eth2_signed_data(client, signed.as_eth2_signed_data().unwrap(), &wrong_pubkey)
                .await
                .unwrap_err();

        assert!(matches!(err, Eth2SignedDataError::Signing(_)));
    }

    #[tokio::test]
    async fn verify_rejects_zero_signature() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let client = mock.client();
        let data: SignedData =
            load::<SignedRandao>("TestJSONSerialisation_SignedRandao.json.golden").into();

        let pubkey = [0x11; 48];
        let signed = data.set_signature([0; SIGNATURE_LENGTH]).unwrap();

        let err = verify_eth2_signed_data(client, signed.as_eth2_signed_data().unwrap(), &pubkey)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Eth2SignedDataError::Signing(SigningError::ZeroSignature)
        ));
    }

    #[test]
    fn registration_always_uses_epoch_zero() {
        // VersionedSignedValidatorRegistration uses DomainApplicationBuilder,
        // which is fixed at epoch 0 regardless of the beacon client.
        let data: SignedData = load::<VersionedSignedValidatorRegistration>(
            "VersionedSignedValidatorRegistration.v1.json",
        )
        .into();
        assert_eq!(
            data.as_eth2_signed_data().unwrap().domain_name(),
            DomainName::ApplicationBuilder
        );
    }

    #[test]
    fn as_eth2_signed_data_views_typed_payloads() {
        let randao: SignedRandao = load("TestJSONSerialisation_SignedRandao.json.golden");

        // A typed payload is viewable as Eth2SignedData...
        let data = SignedData::from(randao);
        assert!(data.as_eth2_signed_data().is_some());

        // ...while a raw signature is not.
        let sig = SignedData::from([0u8; SIGNATURE_LENGTH] as Signature);
        assert!(sig.as_eth2_signed_data().is_none());
    }
}
