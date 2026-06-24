//! SigAgg aggregates threshold partial BLS signatures into a single aggregated
//! signature ready to be broadcast to the beacon chain.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls};
use tracing::{debug, error, info_span};

use crate::{
    signeddata::{SignedDataError, VersionedAttestation},
    types::{Duty, ParSignedData, PubKey, Signature, SignedData},
};

/// Error type for sigagg.
#[derive(Debug, thiserror::Error)]
pub enum SigAggError {
    /// Threshold must be a positive integer.
    #[error("invalid threshold")]
    InvalidThreshold,

    /// Aggregate was called with an empty per-validator map.
    #[error("empty partial signed data set")]
    EmptySet,

    /// A validator entry has fewer partial signatures than the threshold.
    #[error("validator {pubkey}: require threshold signatures")]
    RequireThresholdSignatures {
        /// The validator public key.
        pubkey: PubKey,
    },

    /// After deduplicating by share index, fewer distinct signatures remain
    /// than the threshold.
    #[error("validator {pubkey}: number of partial signatures less than threshold")]
    InsufficientDistinctSignatures {
        /// The validator public key.
        pubkey: PubKey,
    },

    /// Failed to extract the BLS signature bytes from a partial signed data.
    #[error("validator {pubkey}: signature from core: {source}")]
    SignatureFromCore {
        /// The validator public key.
        pubkey: PubKey,
        /// The underlying error.
        #[source]
        source: SignedDataError,
    },

    /// Failed to inject the aggregated signature into the output signed data.
    #[error("validator {pubkey}: set signature: {source}")]
    SetSignature {
        /// The validator public key.
        pubkey: PubKey,
        /// The underlying error.
        #[source]
        source: SignedDataError,
    },

    /// BLS threshold aggregation failed.
    #[error("validator {pubkey}: threshold aggregate: {source}")]
    ThresholdAggregate {
        /// The validator public key.
        pubkey: PubKey,
        /// The underlying error.
        #[source]
        source: pluto_crypto::types::Error,
    },
}

/// Convenience alias for [`std::result::Result`] with [`SigAggError`].
pub type Result<T> = std::result::Result<T, SigAggError>;

/// Per-duty output: one aggregated [`SignedData`] per validator public key.
pub type AggSignedDataSet = HashMap<PubKey, Box<dyn SignedData>>;

/// Callback invoked after a successful threshold aggregation for a duty.
pub type AggSub = Arc<
    dyn Fn(&Duty, &AggSignedDataSet) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync
        + 'static,
>;

/// Verify callback — checks the aggregated signature against the beacon chain.
pub type VerifyFn = Arc<
    dyn Fn(&PubKey, &dyn SignedData) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync
        + 'static,
>;

/// Aggregates threshold partial BLS signatures into a single aggregated
/// signature per validator.
pub struct Aggregator {
    threshold: u64,
    verify_fn: VerifyFn,
    subs: Vec<AggSub>,
}

impl Aggregator {
    /// Creates a new `Aggregator`.
    ///
    /// Returns an error if `threshold` is zero.
    pub fn new(threshold: u64, verify_fn: VerifyFn) -> Result<Self> {
        if threshold == 0 {
            return Err(SigAggError::InvalidThreshold);
        }

        Ok(Self {
            threshold,
            verify_fn,
            subs: Vec::new(),
        })
    }

    /// Registers a callback for aggregated signed duty data.
    pub fn subscribe(&mut self, sub: AggSub) {
        self.subs.push(sub);
    }

    /// Aggregates the partially signed duty data for the set of DVs and
    /// notifies all subscribers.
    ///
    /// If aggregation fails for any validator the entire call returns that
    /// error immediately — no partial results are emitted.
    pub async fn aggregate(
        &self,
        duty: &Duty,
        set: &HashMap<PubKey, Vec<ParSignedData>>,
    ) -> Result<()> {
        if set.is_empty() {
            return Err(SigAggError::EmptySet);
        }

        let mut output = AggSignedDataSet::new();

        for (pubkey, par_sigs) in set {
            let signed = self.aggregate_one(pubkey, par_sigs).await?;
            output.insert(*pubkey, signed);
        }

        debug!("Threshold aggregated partial signatures");

        for sub in &self.subs {
            sub(duty, &output).await?;
        }

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(pubkey = %pubkey))]
    async fn aggregate_one(
        &self,
        pubkey: &PubKey,
        par_sigs: &[ParSignedData],
    ) -> Result<Box<dyn SignedData>> {
        if (par_sigs.len() as u64) < self.threshold {
            return Err(SigAggError::RequireThresholdSignatures { pubkey: *pubkey });
        }

        // Deduplicate by share index; last writer wins (matches Go behaviour).
        let mut bls_sigs: HashMap<u64, Signature> = HashMap::new();
        for par_sig in par_sigs {
            let sig =
                par_sig
                    .signed_data
                    .signature()
                    .map_err(|e| SigAggError::SignatureFromCore {
                        pubkey: *pubkey,
                        source: e,
                    })?;
            bls_sigs.insert(par_sig.share_idx, sig);
        }

        if (bls_sigs.len() as u64) < self.threshold {
            return Err(SigAggError::InsufficientDistinctSignatures { pubkey: *pubkey });
        }

        let span = info_span!("BlstImpl::threshold_aggregate");
        let agg_bytes = {
            let _enter = span.enter();
            BlstImpl.threshold_aggregate(&bls_sigs)
        }
        .map_err(|e| {
            error!(parent: &span, error = %e, "threshold aggregate failed");
            SigAggError::ThresholdAggregate {
                pubkey: *pubkey,
                source: e,
            }
        })?;

        // Prefer a VersionedAttestation that has validator_index set — the local VC
        // includes it, peers don't. Falling back to parSigs[0] is fine for all other
        // duty types, and for attestations where no parSig carries a validator_index.
        // All parSigs share the same unsigned payload (guaranteed by consensus), so
        // any one works as a template.
        let template = par_sigs
            .iter()
            .find_map(|ps| {
                let att = ps
                    .signed_data
                    .as_any()
                    .downcast_ref::<VersionedAttestation>()?;
                att.0.validator_index?; // return an error if validator_index is not set
                Some(ps.signed_data.as_ref())
            })
            .unwrap_or_else(|| par_sigs[0].signed_data.as_ref());

        let agg_signed = template.set_signature_boxed(agg_bytes).map_err(|e| {
            error!(parent: &span, error = %e, "set_signature failed");
            SigAggError::SetSignature {
                pubkey: *pubkey,
                source: e,
            }
        })?;

        (self.verify_fn)(pubkey, agg_signed.as_ref())
            .await
            .map_err(|e| {
                error!(parent: &span, error = %e, "verify failed");
                e
            })?;

        Ok(agg_signed)
    }
}

/// Returns a [`VerifyFn`] that verifies the aggregated signature against the
/// beacon chain.
///
/// TODO: implement once `Eth2SignedData` and beacon-client verification are
/// ported (`core::types` has a placeholder — see types.rs TODO for
/// `Eth2SignedData`). For now callers can use a no-op or BLS-only verifier.
pub fn new_verifier() -> VerifyFn {
    Arc::new(|_, _| Box::pin(async { Ok(()) }))
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Mutex};

    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls};
    use pluto_ssz::HashRoot;

    use super::*;
    use crate::{
        signeddata::{
            SignedDataError, SignedRandao, SignedVoluntaryExit, VersionedSignedProposal,
            VersionedSignedValidatorRegistration,
        },
        types::{SIGNATURE_LENGTH, Signature},
    };

    fn noop_verify() -> VerifyFn {
        Arc::new(|_, _| Box::pin(async { Ok(()) }))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockSignedData {
        sig: [u8; SIGNATURE_LENGTH],
    }

    impl SignedData for MockSignedData {
        fn signature(&self) -> std::result::Result<Signature, SignedDataError> {
            Ok(self.sig)
        }

        fn set_signature(&self, sig: Signature) -> std::result::Result<Self, SignedDataError>
        where
            Self: Sized,
        {
            Ok(Self { sig })
        }

        fn set_signature_boxed(
            &self,
            signature: Signature,
        ) -> std::result::Result<Box<dyn SignedData>, SignedDataError> {
            Ok(Box::new(self.set_signature(signature)?))
        }

        fn message_root(&self) -> std::result::Result<HashRoot, SignedDataError> {
            Ok([0u8; 32])
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FailSignatureMock;

    impl SignedData for FailSignatureMock {
        fn signature(&self) -> std::result::Result<Signature, SignedDataError> {
            Err(SignedDataError::UnknownType)
        }

        fn set_signature(&self, _: Signature) -> std::result::Result<Self, SignedDataError>
        where
            Self: Sized,
        {
            Ok(Self)
        }

        fn set_signature_boxed(
            &self,
            sig: Signature,
        ) -> std::result::Result<Box<dyn SignedData>, SignedDataError> {
            Ok(Box::new(self.set_signature(sig)?))
        }

        fn message_root(&self) -> std::result::Result<HashRoot, SignedDataError> {
            Ok([0u8; 32])
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FailSetSignatureMock {
        sig: [u8; SIGNATURE_LENGTH],
    }

    impl SignedData for FailSetSignatureMock {
        fn signature(&self) -> std::result::Result<Signature, SignedDataError> {
            Ok(self.sig)
        }

        fn set_signature(&self, _: Signature) -> std::result::Result<Self, SignedDataError>
        where
            Self: Sized,
        {
            Err(SignedDataError::UnknownType)
        }

        fn set_signature_boxed(
            &self,
            _: Signature,
        ) -> std::result::Result<Box<dyn SignedData>, SignedDataError> {
            Err(SignedDataError::UnknownType)
        }

        fn message_root(&self) -> std::result::Result<HashRoot, SignedDataError> {
            Ok([0u8; 32])
        }
    }

    fn mock_par_sigs(count: usize, share_idx: u64) -> Vec<ParSignedData> {
        (0..count)
            .map(|_| {
                ParSignedData::new(
                    MockSignedData {
                        sig: [0u8; SIGNATURE_LENGTH],
                    },
                    share_idx,
                )
            })
            .collect()
    }

    struct BLSContext {
        pubkey: [u8; 48],
        sigs: Vec<(u64, [u8; SIGNATURE_LENGTH])>,
        expected_agg: [u8; SIGNATURE_LENGTH],
    }

    fn make_bls_context() -> BLSContext {
        const THRESHOLD: u64 = 3;
        const PEERS: u64 = 4;
        const MSG: [u8; 32] = [42u8; 32];

        let tbls = BlstImpl;
        let mut rng = rand::thread_rng();
        let secret = tbls.generate_secret_key(&mut rng).unwrap();
        let pubkey = tbls.secret_to_public_key(&secret).unwrap();
        let shares = tbls.threshold_split(&secret, PEERS, THRESHOLD).unwrap();

        let mut bls_map: HashMap<u64, [u8; SIGNATURE_LENGTH]> = HashMap::new();
        let mut sigs = Vec::new();
        for (share_idx, share) in &shares {
            let sig = tbls.sign(share, &MSG).unwrap();
            bls_map.insert(*share_idx, sig);
            sigs.push((*share_idx, sig));
        }

        BLSContext {
            pubkey,
            sigs,
            expected_agg: tbls.threshold_aggregate(&bls_map).unwrap(),
        }
    }

    async fn assert_aggregates(
        pubkey: [u8; 48],
        par_sigs: Vec<ParSignedData>,
        expected_agg: [u8; SIGNATURE_LENGTH],
        duty: &Duty,
    ) {
        let received: Arc<Mutex<Option<Signature>>> = Arc::new(Mutex::new(None));
        let received_clone = received.clone();

        let mut agg = Aggregator::new(3, noop_verify()).unwrap();
        agg.subscribe(Arc::new(move |_, set: &AggSignedDataSet| {
            let received_clone = received_clone.clone();
            let sig = set.values().next().unwrap().signature().unwrap();
            Box::pin(async move {
                *received_clone.lock().unwrap() = Some(sig);
                Ok(())
            })
        }));

        let mut set = HashMap::new();
        set.insert(PubKey::new(pubkey), par_sigs);
        agg.aggregate(duty, &set).await.unwrap();

        let received_sig = received.lock().unwrap().take().unwrap();
        assert_eq!(received_sig, expected_agg);
    }

    async fn run_aggregation_test(template: &dyn SignedData, duty: &Duty) {
        let ctx = make_bls_context();
        let par_sigs = ctx
            .sigs
            .iter()
            .map(|(idx, sig)| {
                let signed = template.set_signature_boxed(*sig).unwrap();
                ParSignedData::new_boxed(signed, *idx)
            })
            .collect();
        assert_aggregates(ctx.pubkey, par_sigs, ctx.expected_agg, duty).await;
    }

    #[test]
    fn invalid_threshold() {
        let result = Aggregator::new(0, noop_verify());
        let Err(err) = result else {
            panic!("expected error")
        };
        assert!(matches!(err, SigAggError::InvalidThreshold));
        assert_eq!(err.to_string(), "invalid threshold");
    }

    #[tokio::test]
    async fn require_threshold_signatures() {
        let agg = Aggregator::new(3, noop_verify()).unwrap();
        let mut set = HashMap::new();
        set.insert(PubKey::new([0u8; 48]), vec![]);
        let err = agg
            .aggregate(&Duty::new_attester_duty(1.into()), &set)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SigAggError::RequireThresholdSignatures { .. }
        ));
        assert_eq!(
            err.to_string(),
            format!(
                "validator 0x{}: require threshold signatures",
                "00".repeat(48)
            )
        );
    }

    #[tokio::test]
    async fn aggregate_attester() {
        let ctx = make_bls_context();
        let par_sigs = ctx
            .sigs
            .iter()
            .map(|(idx, sig)| ParSignedData::new(MockSignedData { sig: *sig }, *idx))
            .collect();
        assert_aggregates(
            ctx.pubkey,
            par_sigs,
            ctx.expected_agg,
            &Duty::new_attester_duty(1.into()),
        )
        .await;
    }

    #[tokio::test]
    async fn insufficient_distinct_signatures() {
        // 4 parSigs all with the same share_idx → deduplicates to 1, below threshold 3.
        let agg = Aggregator::new(3, noop_verify()).unwrap();
        let mut set = HashMap::new();
        set.insert(PubKey::new([0u8; 48]), mock_par_sigs(4, 0));
        let err = agg
            .aggregate(&Duty::new_attester_duty(1.into()), &set)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SigAggError::InsufficientDistinctSignatures { .. }
        ));
        assert_eq!(
            err.to_string(),
            format!(
                "validator 0x{}: number of partial signatures less than threshold",
                "00".repeat(48)
            )
        );
    }

    #[tokio::test]
    async fn empty_set() {
        let agg = Aggregator::new(3, noop_verify()).unwrap();
        let err = agg
            .aggregate(&Duty::new_attester_duty(1.into()), &HashMap::new())
            .await
            .unwrap_err();
        assert!(matches!(err, SigAggError::EmptySet));
        assert_eq!(err.to_string(), "empty partial signed data set");
    }

    #[tokio::test]
    async fn multiple_subscribers_all_notified() {
        const THRESHOLD: u64 = 3;
        const PEERS: u64 = 4;

        let tbls = BlstImpl;
        let mut rng = rand::thread_rng();

        let secret = tbls.generate_secret_key(&mut rng).unwrap();
        let pubkey = tbls.secret_to_public_key(&secret).unwrap();
        let shares = tbls.threshold_split(&secret, PEERS, THRESHOLD).unwrap();

        let msg = [7u8; 32];
        let mut par_sigs = Vec::new();
        for (share_idx, share) in &shares {
            let sig = tbls.sign(share, &msg).unwrap();
            par_sigs.push(ParSignedData::new(MockSignedData { sig }, *share_idx));
        }

        let mut agg = Aggregator::new(THRESHOLD, noop_verify()).unwrap();

        let count: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));

        for _ in 0..3 {
            let count = count.clone();
            agg.subscribe(Arc::new(move |_, _| {
                let count = count.clone();
                Box::pin(async move {
                    *count.lock().unwrap() += 1;
                    Ok(())
                })
            }));
        }

        let mut set = HashMap::new();
        set.insert(PubKey::new(pubkey), par_sigs);
        agg.aggregate(&Duty::new_attester_duty(1.into()), &set)
            .await
            .unwrap();

        assert_eq!(*count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn deduplication_succeeds() {
        // 5 parSigs with 4 distinct share indices (one duplicate) at threshold 3 →
        // success.
        let ctx = make_bls_context();
        let mut par_sigs: Vec<ParSignedData> = ctx
            .sigs
            .iter()
            .map(|(idx, sig)| ParSignedData::new(MockSignedData { sig: *sig }, *idx))
            .collect();

        // Add a duplicate of the first share — last writer wins, same sig so result
        // identical.
        let (first_idx, first_sig) = ctx.sigs[0];
        par_sigs.push(ParSignedData::new(
            MockSignedData { sig: first_sig },
            first_idx,
        ));

        assert_aggregates(
            ctx.pubkey,
            par_sigs,
            ctx.expected_agg,
            &Duty::new_attester_duty(1.into()),
        )
        .await;
    }

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("signeddata")
            .join(name)
    }

    #[tokio::test]
    async fn aggregate_randao() {
        let json = fs::read_to_string(fixture_path(
            "TestJSONSerialisation_SignedRandao.json.golden",
        ))
        .unwrap();
        let template: SignedRandao = serde_json::from_str(&json).unwrap();
        run_aggregation_test(&template, &Duty::new_randao_duty(1.into())).await;
    }

    #[tokio::test]
    async fn aggregate_exit() {
        let json = fs::read_to_string(fixture_path(
            "TestJSONSerialisation_SignedVoluntaryExit.json.golden",
        ))
        .unwrap();
        let template: SignedVoluntaryExit = serde_json::from_str(&json).unwrap();
        run_aggregation_test(&template, &Duty::new_voluntary_exit_duty(1.into())).await;
    }

    #[tokio::test]
    async fn aggregate_proposer() {
        let json = fs::read_to_string(fixture_path(
            "TestJSONSerialisation_VersionedSignedProposal.json.golden",
        ))
        .unwrap();
        let template: VersionedSignedProposal = serde_json::from_str(&json).unwrap();
        run_aggregation_test(&template, &Duty::new_proposer_duty(1.into())).await;
    }

    #[tokio::test]
    async fn aggregate_builder_proposer() {
        let json = fs::read_to_string(fixture_path(
            "TestJSONSerialisation_VersionedSignedProposal.json#01.golden",
        ))
        .unwrap();
        let template: VersionedSignedProposal = serde_json::from_str(&json).unwrap();
        run_aggregation_test(&template, &Duty::new_builder_proposer_duty(1.into())).await;
    }

    #[tokio::test]
    async fn aggregate_builder_registration() {
        let json = fs::read_to_string(fixture_path("VersionedSignedValidatorRegistration.v1.json"))
            .unwrap();
        let template: VersionedSignedValidatorRegistration = serde_json::from_str(&json).unwrap();
        run_aggregation_test(&template, &Duty::new_builder_registration_duty(1.into())).await;
    }

    #[tokio::test]
    async fn multiple_validators() {
        // Two independent validators aggregated in a single aggregate() call.
        const THRESHOLD: u64 = 3;
        const PEERS: u64 = 4;

        let tbls = BlstImpl;
        let mut rng = rand::thread_rng();
        let msg = [55u8; 32];

        let mut agg_set: HashMap<PubKey, Vec<ParSignedData>> = HashMap::new();
        let mut expected: HashMap<PubKey, [u8; SIGNATURE_LENGTH]> = HashMap::new();

        for _ in 0..2 {
            let secret = tbls.generate_secret_key(&mut rng).unwrap();
            let pubkey_bytes = tbls.secret_to_public_key(&secret).unwrap();
            let shares = tbls.threshold_split(&secret, PEERS, THRESHOLD).unwrap();

            let mut par_sigs = Vec::new();
            let mut bls_map: HashMap<u64, [u8; SIGNATURE_LENGTH]> = HashMap::new();
            for (share_idx, share) in &shares {
                let sig = tbls.sign(share, &msg).unwrap();
                bls_map.insert(*share_idx, sig);
                par_sigs.push(ParSignedData::new(MockSignedData { sig }, *share_idx));
            }

            let agg_sig = tbls.threshold_aggregate(&bls_map).unwrap();
            let pubkey = PubKey::new(pubkey_bytes);
            expected.insert(pubkey, agg_sig);
            agg_set.insert(pubkey, par_sigs);
        }

        let received: Arc<Mutex<HashMap<PubKey, Signature>>> = Arc::new(Mutex::new(HashMap::new()));
        let received_clone = received.clone();

        let mut agg = Aggregator::new(THRESHOLD, noop_verify()).unwrap();
        agg.subscribe(Arc::new(move |_, set: &AggSignedDataSet| {
            let received_clone = received_clone.clone();
            let sigs: HashMap<PubKey, Signature> = set
                .iter()
                .map(|(k, v)| (*k, v.signature().unwrap()))
                .collect();
            Box::pin(async move {
                received_clone.lock().unwrap().extend(sigs);
                Ok(())
            })
        }));

        agg.aggregate(&Duty::new_attester_duty(1.into()), &agg_set)
            .await
            .unwrap();

        let received = received.lock().unwrap();
        assert_eq!(received.len(), 2);
        for (pubkey, exp_bytes) in &expected {
            let got = &received[pubkey];
            assert_eq!(got, exp_bytes);
        }
    }

    #[tokio::test]
    async fn verify_fn_error() {
        let ctx = make_bls_context();
        let par_sigs: Vec<ParSignedData> = ctx
            .sigs
            .iter()
            .map(|(idx, sig)| ParSignedData::new(MockSignedData { sig: *sig }, *idx))
            .collect();

        let fail_verify: VerifyFn =
            Arc::new(|_, _| Box::pin(async { Err(SigAggError::InvalidThreshold) }));
        let agg = Aggregator::new(3, fail_verify).unwrap();
        let mut set = HashMap::new();
        set.insert(PubKey::new(ctx.pubkey), par_sigs);
        let err = agg
            .aggregate(&Duty::new_attester_duty(1.into()), &set)
            .await
            .unwrap_err();
        assert!(matches!(err, SigAggError::InvalidThreshold));
    }

    #[tokio::test]
    async fn subscriber_error() {
        let ctx = make_bls_context();
        let par_sigs: Vec<ParSignedData> = ctx
            .sigs
            .iter()
            .map(|(idx, sig)| ParSignedData::new(MockSignedData { sig: *sig }, *idx))
            .collect();

        let mut agg = Aggregator::new(3, noop_verify()).unwrap();
        agg.subscribe(Arc::new(|_, _| {
            Box::pin(async { Err(SigAggError::InvalidThreshold) })
        }));
        let mut set = HashMap::new();
        set.insert(PubKey::new(ctx.pubkey), par_sigs);
        let err = agg
            .aggregate(&Duty::new_attester_duty(1.into()), &set)
            .await
            .unwrap_err();
        assert!(matches!(err, SigAggError::InvalidThreshold));
    }

    #[tokio::test]
    async fn signature_from_core_error() {
        let agg = Aggregator::new(3, noop_verify()).unwrap();
        let par_sigs: Vec<ParSignedData> = (0..3u64)
            .map(|i| ParSignedData::new(FailSignatureMock, i))
            .collect();
        let mut set = HashMap::new();
        set.insert(PubKey::new([1u8; 48]), par_sigs);
        let err = agg
            .aggregate(&Duty::new_attester_duty(1.into()), &set)
            .await
            .unwrap_err();
        assert!(matches!(err, SigAggError::SignatureFromCore { .. }));
    }

    #[tokio::test]
    async fn set_signature_error() {
        let ctx = make_bls_context();
        let par_sigs: Vec<ParSignedData> = ctx
            .sigs
            .iter()
            .map(|(idx, sig)| ParSignedData::new(FailSetSignatureMock { sig: *sig }, *idx))
            .collect();

        let agg = Aggregator::new(3, noop_verify()).unwrap();
        let mut set = HashMap::new();
        set.insert(PubKey::new(ctx.pubkey), par_sigs);
        let err = agg
            .aggregate(&Duty::new_attester_duty(1.into()), &set)
            .await
            .unwrap_err();
        assert!(matches!(err, SigAggError::SetSignature { .. }));
    }

    #[tokio::test]
    async fn versioned_attestation_validator_index_preference() {
        let json = fs::read_to_string(fixture_path(
            "TestJSONSerialisation_VersionedAttestation.json.golden",
        ))
        .unwrap();
        let with_idx: VersionedAttestation = serde_json::from_str(&json).unwrap();
        assert!(
            with_idx.0.validator_index.is_some(),
            "fixture must carry validator_index"
        );

        let mut inner_no_idx = with_idx.0.clone();
        inner_no_idx.validator_index = None;
        let without_idx = VersionedAttestation::new(inner_no_idx).unwrap();

        let ctx = make_bls_context();
        // First par_sig has no validator_index; second has it — template must prefer
        // the latter.
        let par_sigs: Vec<ParSignedData> = ctx
            .sigs
            .iter()
            .enumerate()
            .map(|(i, (idx, sig))| {
                let template: &dyn SignedData = if i == 0 { &without_idx } else { &with_idx };
                let signed = template.set_signature_boxed(*sig).unwrap();
                ParSignedData::new_boxed(signed, *idx)
            })
            .collect();

        let captured: Arc<Mutex<Option<Box<dyn SignedData>>>> = Arc::new(Mutex::new(None));
        let captured_clone = captured.clone();

        let mut agg = Aggregator::new(3, noop_verify()).unwrap();
        agg.subscribe(Arc::new(move |_, set: &AggSignedDataSet| {
            let captured_clone = captured_clone.clone();
            let output = set.values().next().unwrap().clone();
            Box::pin(async move {
                *captured_clone.lock().unwrap() = Some(output);
                Ok(())
            })
        }));

        let mut set = HashMap::new();
        set.insert(PubKey::new(ctx.pubkey), par_sigs);
        agg.aggregate(&Duty::new_attester_duty(1.into()), &set)
            .await
            .unwrap();

        let output = captured.lock().unwrap().take().unwrap();
        let att = output
            .as_any()
            .downcast_ref::<VersionedAttestation>()
            .expect("output must be VersionedAttestation");
        assert!(
            att.0.validator_index.is_some(),
            "output must preserve validator_index from template"
        );
    }
}
