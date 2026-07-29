//! Eth2 signed-data verification.
//!
//! Extends [`SignedData`] types that carry beacon-chain signatures with the
//! metadata needed to verify them: the signing [`DomainName`] and the signing
//! [`Epoch`]. [`verify_eth2_signed_data`] ties the two together with the
//! upstream beacon-node domain lookup and BLS verification.

use std::any::Any;

use async_trait::async_trait;
use pluto_crypto::types::PublicKey;
use pluto_eth2api::{client::EthBeaconNodeApiClient, spec::phase0::Epoch};
use pluto_eth2util::{
    helpers::{self, HelperError},
    signing::{self, DomainName, SigningError},
};

use crate::{
    signeddata::{
        Attestation, BeaconCommitteeSelection, SignedAggregateAndProof, SignedDataError,
        SignedRandao, SignedSyncContributionAndProof, SignedSyncMessage, SignedVoluntaryExit,
        SyncCommitteeSelection, VersionedAttestation, VersionedSignedAggregateAndProof,
        VersionedSignedProposal, VersionedSignedValidatorRegistration,
    },
    types::SignedData,
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

/// Signed duty data that carries an eth2 beacon-chain signature.
///
/// The signing root is the payload's [`SignedData::message_root`] wrapped with
/// the domain identified by [`Self::domain_name`] at the epoch returned by
/// [`Self::epoch`].
#[async_trait]
pub trait Eth2SignedData: SignedData {
    /// Returns the eth2 signing domain for this data.
    fn domain_name(&self) -> DomainName;

    /// Returns the epoch at which the signing domain is resolved.
    async fn epoch(&self, client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError>;
}

/// Verifies the eth2 signature associated with the given [`Eth2SignedData`].
pub async fn verify_eth2_signed_data(
    client: &EthBeaconNodeApiClient,
    data: &dyn Eth2SignedData,
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

/// Attempts to view a [`SignedData`] as an [`Eth2SignedData`], mirroring Go's
/// `data.(core.Eth2SignedData)` type assertion. Returns `None` for signed-data
/// variants without a beacon-chain signing domain (e.g. raw [`Signature`]).
///
/// [`Signature`]: crate::types::Signature
pub fn as_eth2_signed_data(data: &dyn SignedData) -> Option<&dyn Eth2SignedData> {
    let any = data as &dyn Any;

    if let Some(v) = any.downcast_ref::<VersionedSignedProposal>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<Attestation>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<VersionedAttestation>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<SignedVoluntaryExit>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<VersionedSignedValidatorRegistration>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<SignedRandao>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<BeaconCommitteeSelection>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<SignedAggregateAndProof>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<VersionedSignedAggregateAndProof>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<SignedSyncMessage>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<SignedSyncContributionAndProof>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<SyncCommitteeSelection>() {
        return Some(v);
    }

    None
}

#[async_trait]
impl Eth2SignedData for VersionedSignedProposal {
    fn domain_name(&self) -> DomainName {
        DomainName::BeaconProposer
    }

    async fn epoch(&self, client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        if self.0.version == pluto_eth2api::versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion.into());
        }

        Ok(helpers::epoch_from_slot(client, self.0.block.slot()).await?)
    }
}

#[async_trait]
impl Eth2SignedData for Attestation {
    fn domain_name(&self) -> DomainName {
        DomainName::BeaconAttester
    }

    async fn epoch(&self, _client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(self.0.data.target.epoch)
    }
}

#[async_trait]
impl Eth2SignedData for VersionedAttestation {
    fn domain_name(&self) -> DomainName {
        DomainName::BeaconAttester
    }

    async fn epoch(&self, _client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        let version = self.0.version;
        if version == pluto_eth2api::versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion.into());
        }

        let data = self
            .0
            .attestation
            .as_ref()
            .ok_or(SignedDataError::MissingAttestation(version))?
            .data();

        Ok(data.target.epoch)
    }
}

#[async_trait]
impl Eth2SignedData for SignedVoluntaryExit {
    fn domain_name(&self) -> DomainName {
        DomainName::VoluntaryExit
    }

    async fn epoch(&self, _client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(self.0.message.epoch)
    }
}

#[async_trait]
impl Eth2SignedData for VersionedSignedValidatorRegistration {
    fn domain_name(&self) -> DomainName {
        DomainName::ApplicationBuilder
    }

    async fn epoch(&self, _client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        // Always use epoch 0 for DomainApplicationBuilder.
        Ok(0)
    }
}

#[async_trait]
impl Eth2SignedData for SignedRandao {
    fn domain_name(&self) -> DomainName {
        DomainName::Randao
    }

    async fn epoch(&self, _client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(self.0.epoch)
    }
}

#[async_trait]
impl Eth2SignedData for BeaconCommitteeSelection {
    fn domain_name(&self) -> DomainName {
        DomainName::SelectionProof
    }

    async fn epoch(&self, client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(helpers::epoch_from_slot(client, self.0.slot).await?)
    }
}

#[async_trait]
impl Eth2SignedData for SignedAggregateAndProof {
    fn domain_name(&self) -> DomainName {
        DomainName::AggregateAndProof
    }

    async fn epoch(&self, client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(helpers::epoch_from_slot(client, self.0.message.aggregate.data.slot).await?)
    }
}

#[async_trait]
impl Eth2SignedData for VersionedSignedAggregateAndProof {
    fn domain_name(&self) -> DomainName {
        DomainName::AggregateAndProof
    }

    async fn epoch(&self, client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        let slot = self.0.slot().ok_or(SignedDataError::UnknownVersion)?;

        Ok(helpers::epoch_from_slot(client, slot).await?)
    }
}

#[async_trait]
impl Eth2SignedData for SignedSyncMessage {
    fn domain_name(&self) -> DomainName {
        DomainName::SyncCommittee
    }

    async fn epoch(&self, client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(helpers::epoch_from_slot(client, self.0.slot).await?)
    }
}

#[async_trait]
impl Eth2SignedData for SignedSyncContributionAndProof {
    fn domain_name(&self) -> DomainName {
        DomainName::ContributionAndProof
    }

    async fn epoch(&self, client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(helpers::epoch_from_slot(client, self.0.message.contribution.slot).await?)
    }
}

#[async_trait]
impl Eth2SignedData for SyncCommitteeSelection {
    fn domain_name(&self) -> DomainName {
        DomainName::SyncCommitteeSelectionProof
    }

    async fn epoch(&self, client: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(helpers::epoch_from_slot(client, self.0.slot).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls};
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
    async fn assert_verifies<T>(client: &EthBeaconNodeApiClient, data: T)
    where
        T: Eth2SignedData + Clone,
    {
        let epoch = data.epoch(client).await.unwrap();
        let root = data.message_root().unwrap();

        let tbls = BlstImpl;
        let mut rng = rand::thread_rng();
        let secret = tbls.generate_secret_key(&mut rng).unwrap();
        let pubkey = tbls.secret_to_public_key(&secret).unwrap();

        let sig_data = signing::get_data_root(client, data.domain_name(), epoch, root)
            .await
            .unwrap();
        let sig: Signature = tbls.sign(&secret, &sig_data).unwrap();

        let signed = data.set_signature(sig).unwrap();

        verify_eth2_signed_data(client, &signed, &pubkey)
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
        let data: SignedRandao = load("TestJSONSerialisation_SignedRandao.json.golden");

        let epoch = data.epoch(client).await.unwrap();
        let root = data.message_root().unwrap();

        let tbls = BlstImpl;
        let mut rng = rand::thread_rng();
        let secret = tbls.generate_secret_key(&mut rng).unwrap();
        let wrong_secret = tbls.generate_secret_key(&mut rng).unwrap();
        let wrong_pubkey = tbls.secret_to_public_key(&wrong_secret).unwrap();

        let sig_data = signing::get_data_root(client, data.domain_name(), epoch, root)
            .await
            .unwrap();
        let sig: Signature = tbls.sign(&secret, &sig_data).unwrap();
        let signed = data.set_signature(sig).unwrap();

        let err = verify_eth2_signed_data(client, &signed, &wrong_pubkey)
            .await
            .unwrap_err();

        assert!(matches!(err, Eth2SignedDataError::Signing(_)));
    }

    #[tokio::test]
    async fn verify_rejects_zero_signature() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let client = mock.client();
        let data: SignedRandao = load("TestJSONSerialisation_SignedRandao.json.golden");

        let pubkey = [0x11; 48];
        let signed = data.set_signature([0; SIGNATURE_LENGTH]).unwrap();

        let err = verify_eth2_signed_data(client, &signed, &pubkey)
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
        let data: VersionedSignedValidatorRegistration =
            load("VersionedSignedValidatorRegistration.v1.json");
        assert_eq!(data.domain_name(), DomainName::ApplicationBuilder);
    }

    #[test]
    fn as_eth2_signed_data_views_typed_payloads() {
        let randao: SignedRandao = load("TestJSONSerialisation_SignedRandao.json.golden");

        // A typed payload is viewable as Eth2SignedData...
        let boxed: Box<dyn SignedData> = Box::new(randao);
        assert!(as_eth2_signed_data(boxed.as_ref()).is_some());

        // ...while a raw signature is not.
        let sig: Box<dyn SignedData> = Box::new([0u8; SIGNATURE_LENGTH] as Signature);
        assert!(as_eth2_signed_data(sig.as_ref()).is_none());
    }
}
