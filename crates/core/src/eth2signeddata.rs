//! eth2 BLS signature verification for signed duty data.
//!
//! Ports Charon's `core.VerifyEth2SignedData`
//! ([`eth2signeddata.go`](https://github.com/ObolNetwork/charon/blob/main/core/eth2signeddata.go)).
//!
//! [`SignedData`] only exposes the signature and message root. eth2 signature
//! verification additionally needs the signing domain (which depends on a
//! per-type [`DomainName`]) and the epoch the data belongs to. This module adds
//! the [`Eth2SignedData`] trait — mirroring Charon's `core.Eth2SignedData`
//! interface — implementing it for every signed-data type that Charon does, and
//! the [`verify_eth2_signed_data`] helper that ties them together with the
//! eth2util signing primitives.

use async_trait::async_trait;
use pluto_crypto::types::PublicKey;
use pluto_eth2api::{EthBeaconNodeApiClient, spec::phase0::Epoch};
use pluto_eth2util::{helpers::epoch_from_slot, signing};

use crate::{
    signeddata::{
        Attestation, BeaconCommitteeSelection, SignedAggregateAndProof, SignedDataError,
        SignedRandao, SignedSyncContributionAndProof, SignedSyncMessage, SignedVoluntaryExit,
        SyncCommitteeSelection, VersionedAttestation, VersionedSignedAggregateAndProof,
        VersionedSignedProposal, VersionedSignedValidatorRegistration,
    },
    types::SignedData,
};

/// Error returned by [`verify_eth2_signed_data`].
#[derive(Debug, thiserror::Error)]
pub enum Eth2SignedDataError {
    /// The signed-data value does not implement [`Eth2SignedData`], so its
    /// domain/epoch cannot be derived (mirrors Charon's failed
    /// `data.(core.Eth2SignedData)` type assertion).
    #[error("signed data is not an eth2 signed data type")]
    NotEth2SignedData,

    /// Deriving the message root, slot, or epoch from the signed data failed.
    #[error(transparent)]
    SignedData(#[from] SignedDataError),

    /// Resolving the epoch from a slot via the beacon node failed.
    #[error(transparent)]
    Epoch(#[from] pluto_eth2util::helpers::HelperError),

    /// The underlying eth2 signature check (domain lookup + BLS verify) failed.
    #[error(transparent)]
    Signing(#[from] signing::SigningError),
}

/// eth2 BLS signature metadata for a signed duty data type.
///
/// Mirrors Charon's `core.Eth2SignedData`: it extends [`SignedData`] with the
/// signing [`DomainName`] and the [`Epoch`] of the underlying message, the two
/// inputs (besides the message root and signature) needed to verify an eth2
/// BLS signature.
#[async_trait]
pub trait Eth2SignedData: SignedData {
    /// Returns the signing domain name associated with the signed data.
    fn domain_name(&self) -> signing::DomainName;

    /// Returns the epoch associated with the underlying message.
    ///
    /// Some types derive the epoch from a slot, which requires the beacon
    /// node's `SLOTS_PER_EPOCH`, hence the client argument and the async
    /// signature.
    async fn epoch(&self, eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError>;
}

/// Verifies the eth2 BLS signature of `data` against `pubkey`.
///
/// Ports Charon's `core.VerifyEth2SignedData`: it derives the epoch and domain
/// name from the [`Eth2SignedData`] surface and the message root from
/// [`SignedData`], resolves the eth2 signing root for that domain/epoch via the
/// beacon node, and verifies the BLS signature.
///
/// `data` is taken as `&dyn SignedData` (matching how signed data flows through
/// the pipeline); it is upcast to [`Eth2SignedData`] via
/// [`as_eth2_signed_data`] — the equivalent of Charon's
/// `data.(core.Eth2SignedData)` assertion — and
/// returns [`Eth2SignedDataError::NotEth2SignedData`] when the concrete type
/// has no eth2 mapping.
pub async fn verify_eth2_signed_data(
    eth2_cl: &EthBeaconNodeApiClient,
    data: &dyn SignedData,
    pubkey: PublicKey,
) -> Result<(), Eth2SignedDataError> {
    let data = as_eth2_signed_data(data).ok_or(Eth2SignedDataError::NotEth2SignedData)?;

    let epoch = data.epoch(eth2_cl).await?;
    let sig_root = data.message_root()?;
    let signature = data.signature()?;

    signing::verify(
        eth2_cl,
        data.domain_name(),
        epoch,
        sig_root,
        &signature,
        &pubkey,
    )
    .await?;

    Ok(())
}

/// Upcasts a `&dyn SignedData` to a `&dyn Eth2SignedData` when the concrete
/// type implements it, mirroring Charon's `data.(core.Eth2SignedData)` type
/// assertion.
///
/// Returns `None` for signed-data types without an eth2 domain/epoch mapping
/// (e.g. a bare [`Signature`](crate::types::Signature)).
pub fn as_eth2_signed_data(data: &dyn SignedData) -> Option<&dyn Eth2SignedData> {
    let any = data.as_any();

    // The set must stay in sync with the `impl Eth2SignedData` blocks below
    // (and with Charon's `eth2signeddata.go` assertions).
    macro_rules! try_downcast {
        ($($ty:ty),* $(,)?) => {
            $(
                if let Some(value) = any.downcast_ref::<$ty>() {
                    return Some(value as &dyn Eth2SignedData);
                }
            )*
        };
    }

    try_downcast!(
        VersionedSignedProposal,
        Attestation,
        VersionedAttestation,
        SignedVoluntaryExit,
        VersionedSignedValidatorRegistration,
        SignedRandao,
        BeaconCommitteeSelection,
        SignedAggregateAndProof,
        VersionedSignedAggregateAndProof,
        SignedSyncMessage,
        SignedSyncContributionAndProof,
        SyncCommitteeSelection,
    );

    None
}

// ── Eth2SignedData implementations ───────────────────────────────────────
//
// Each mapping (domain name + epoch) follows Charon's `eth2signeddata.go`
// exactly.

#[async_trait]
impl Eth2SignedData for VersionedSignedProposal {
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::BeaconProposer
    }

    async fn epoch(&self, eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        let slot = self.slot()?;
        Ok(epoch_from_slot(eth2_cl, slot).await?)
    }
}

#[async_trait]
impl Eth2SignedData for Attestation {
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::BeaconAttester
    }

    async fn epoch(&self, _eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(self.0.data.target.epoch)
    }
}

#[async_trait]
impl Eth2SignedData for VersionedAttestation {
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::BeaconAttester
    }

    async fn epoch(&self, _eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        let version = self.0.version;
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
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::VoluntaryExit
    }

    async fn epoch(&self, _eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(self.0.message.epoch)
    }
}

#[async_trait]
impl Eth2SignedData for VersionedSignedValidatorRegistration {
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::ApplicationBuilder
    }

    async fn epoch(&self, _eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        // Always use epoch 0 for DomainApplicationBuilder.
        Ok(0)
    }
}

#[async_trait]
impl Eth2SignedData for SignedRandao {
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::Randao
    }

    async fn epoch(&self, _eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(self.0.epoch)
    }
}

#[async_trait]
impl Eth2SignedData for BeaconCommitteeSelection {
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::SelectionProof
    }

    async fn epoch(&self, eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(epoch_from_slot(eth2_cl, self.0.slot).await?)
    }
}

#[async_trait]
impl Eth2SignedData for SignedAggregateAndProof {
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::AggregateAndProof
    }

    async fn epoch(&self, eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        let slot = self.0.message.aggregate.data.slot;
        Ok(epoch_from_slot(eth2_cl, slot).await?)
    }
}

#[async_trait]
impl Eth2SignedData for VersionedSignedAggregateAndProof {
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::AggregateAndProof
    }

    async fn epoch(&self, eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        let slot = self.0.slot().ok_or(SignedDataError::UnknownVersion)?;
        Ok(epoch_from_slot(eth2_cl, slot).await?)
    }
}

#[async_trait]
impl Eth2SignedData for SignedSyncMessage {
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::SyncCommittee
    }

    async fn epoch(&self, eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(epoch_from_slot(eth2_cl, self.0.slot).await?)
    }
}

#[async_trait]
impl Eth2SignedData for SignedSyncContributionAndProof {
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::ContributionAndProof
    }

    async fn epoch(&self, eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        let slot = self.0.message.contribution.slot;
        Ok(epoch_from_slot(eth2_cl, slot).await?)
    }
}

#[async_trait]
impl Eth2SignedData for SyncCommitteeSelection {
    fn domain_name(&self) -> signing::DomainName {
        signing::DomainName::SyncCommitteeSelectionProof
    }

    async fn epoch(&self, eth2_cl: &EthBeaconNodeApiClient) -> Result<Epoch, Eth2SignedDataError> {
        Ok(epoch_from_slot(eth2_cl, self.0.slot).await?)
    }
}

#[cfg(test)]
mod tests {
    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::PrivateKey};
    use pluto_eth2api::{spec::phase0, v1};
    use pluto_eth2util::signing::{DomainName, get_data_root};
    use pluto_testutil::BeaconMock;

    use super::*;
    use crate::signeddata::Attestation;

    fn secret_key(hex_value: &str) -> PrivateKey {
        let bytes = hex::decode(hex_value).unwrap();
        bytes.as_slice().try_into().unwrap()
    }

    /// Default mock: full simnet spec (all domain types, `SLOTS_PER_EPOCH=16`,
    /// fork schedule and genesis validators root), sufficient to resolve any
    /// signing domain.
    async fn mock_beacon_client() -> BeaconMock {
        BeaconMock::builder().build().await.unwrap()
    }

    fn sample_attestation(target_epoch: phase0::Epoch) -> Attestation {
        let data = phase0::AttestationData {
            slot: 32,
            index: 2,
            beacon_block_root: [0x11; 32],
            source: phase0::Checkpoint {
                epoch: target_epoch.saturating_sub(1),
                root: [0x22; 32],
            },
            target: phase0::Checkpoint {
                epoch: target_epoch,
                root: [0x33; 32],
            },
        };

        Attestation::new(phase0::Attestation {
            aggregation_bits: serde_json::from_str("\"0x0101\"").unwrap(),
            data,
            signature: [0; 96],
        })
    }

    fn sample_beacon_committee_selection(slot: phase0::Slot) -> BeaconCommitteeSelection {
        BeaconCommitteeSelection::new(v1::BeaconCommitteeSelection {
            slot,
            validator_index: 2,
            selection_proof: [0; 96],
        })
    }

    /// Signs the eth2 signing root of `data` for the given domain/epoch with
    /// `secret`, and returns a copy of `data` carrying that signature.
    async fn sign<T>(
        client: &EthBeaconNodeApiClient,
        secret: &PrivateKey,
        data: &T,
        domain: DomainName,
        epoch: phase0::Epoch,
    ) -> T
    where
        T: SignedData + Sized,
    {
        let message_root = data.message_root().unwrap();
        let signing_root = get_data_root(client, domain, epoch, message_root)
            .await
            .unwrap();
        let signature = BlstImpl.sign(secret, &signing_root).unwrap();
        data.set_signature(signature).unwrap()
    }

    #[tokio::test]
    async fn verify_accepts_valid_attestation() {
        let mock = mock_beacon_client().await;
        let client = mock.client();

        let secret = secret_key("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b");
        let pubkey = BlstImpl.secret_to_public_key(&secret).unwrap();

        let att = sample_attestation(4);
        let signed = sign(client, &secret, &att, DomainName::BeaconAttester, 4).await;

        verify_eth2_signed_data(client, &signed, pubkey)
            .await
            .expect("valid attestation signature verifies");
    }

    #[tokio::test]
    async fn verify_rejects_attestation_signed_by_wrong_key() {
        let mock = mock_beacon_client().await;
        let client = mock.client();

        let signer = secret_key("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b");
        let other = secret_key("01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d");
        let wrong_pubkey = BlstImpl.secret_to_public_key(&other).unwrap();

        let att = sample_attestation(4);
        let signed = sign(client, &signer, &att, DomainName::BeaconAttester, 4).await;

        let err = verify_eth2_signed_data(client, &signed, wrong_pubkey)
            .await
            .expect_err("attestation signed by a different key is rejected");

        assert!(matches!(err, Eth2SignedDataError::Signing(_)));
    }

    #[tokio::test]
    async fn verify_accepts_valid_beacon_committee_selection() {
        let mock = mock_beacon_client().await;
        let client = mock.client();

        let secret = secret_key("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b");
        let pubkey = BlstImpl.secret_to_public_key(&secret).unwrap();

        // SLOTS_PER_EPOCH is 16 in the mock spec, so slot 48 → epoch 3.
        let selection = sample_beacon_committee_selection(48);
        let signed = sign(client, &secret, &selection, DomainName::SelectionProof, 3).await;

        verify_eth2_signed_data(client, &signed, pubkey)
            .await
            .expect("valid selection-proof signature verifies");
    }

    #[tokio::test]
    async fn verify_rejects_selection_signed_for_wrong_domain() {
        let mock = mock_beacon_client().await;
        let client = mock.client();

        let secret = secret_key("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b");
        let pubkey = BlstImpl.secret_to_public_key(&secret).unwrap();

        // Sign the selection under the attester domain instead of the
        // selection-proof domain the verifier resolves for this type, so the
        // signing roots differ and verification must fail.
        let selection = sample_beacon_committee_selection(48);
        let signed = sign(client, &secret, &selection, DomainName::BeaconAttester, 3).await;

        let err = verify_eth2_signed_data(client, &signed, pubkey)
            .await
            .expect_err("signature over the wrong domain is rejected");

        assert!(matches!(err, Eth2SignedDataError::Signing(_)));
    }

    #[tokio::test]
    async fn verify_rejects_non_eth2_signed_data() {
        let mock = mock_beacon_client().await;
        let client = mock.client();

        // A bare `Signature` implements `SignedData` but not `Eth2SignedData`.
        let signature: crate::types::Signature = [0x11; 96];

        let err = verify_eth2_signed_data(client, &signature, [0x22; 48])
            .await
            .expect_err("non-eth2 signed data is rejected");

        assert!(matches!(err, Eth2SignedDataError::NotEth2SignedData));
    }
}
