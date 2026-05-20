/// SigAgg aggregates threshold partial BLS signatures into a single aggregated
/// signature ready to be broadcast to the beacon chain.
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls};

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
    #[error("require threshold signatures")]
    RequireThresholdSignatures,

    /// After deduplicating by share index, fewer distinct signatures remain
    /// than the threshold.
    #[error("number of partial signatures less than threshold")]
    InsufficientDistinctSignatures,

    /// Failed to extract the BLS signature bytes from a partial signed data.
    #[error("signature from core: {0}")]
    SignatureFromCore(#[from] SignedDataError),

    /// BLS threshold aggregation failed.
    #[error("threshold aggregate: {0}")]
    ThresholdAggregate(pluto_crypto::types::Error),
}

type Result<T> = std::result::Result<T, SigAggError>;

/// Per-duty output: one aggregated [`SignedData`] per validator public key.
pub type AggSignedDataSet = HashMap<PubKey, Box<dyn SignedData>>;

/// Callback invoked after a successful threshold aggregation for a duty.
pub type AggSub = Arc<
    dyn Fn(&Duty, &AggSignedDataSet) -> Pin<Box<dyn Future<Output = Result<()>> + Send + Sync>>
        + Send
        + Sync
        + 'static,
>;

/// Verify callback — checks the aggregated signature against the beacon chain.
pub type VerifyFn = Arc<
    dyn Fn(&PubKey, &dyn SignedData) -> Pin<Box<dyn Future<Output = Result<()>> + Send + Sync>>
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
    pub async fn aggregate(
        &self,
        duty: &Duty,
        set: HashMap<PubKey, Vec<ParSignedData>>,
    ) -> Result<()> {
        if set.is_empty() {
            return Err(SigAggError::EmptySet);
        }

        let mut output = AggSignedDataSet::new();

        for (pubkey, par_sigs) in &set {
            let signed = self.aggregate_one(pubkey, par_sigs).await?;
            output.insert(*pubkey, signed);
        }

        for sub in &self.subs {
            sub(duty, &output).await?;
        }

        Ok(())
    }

    async fn aggregate_one(
        &self,
        pubkey: &PubKey,
        par_sigs: &[ParSignedData],
    ) -> Result<Box<dyn SignedData>> {
        if (par_sigs.len() as u64) < self.threshold {
            return Err(SigAggError::RequireThresholdSignatures);
        }

        // Deduplicate by share index; last writer wins (matches Go behaviour).
        let mut bls_sigs: HashMap<u64, Signature> = HashMap::new();
        for par_sig in par_sigs {
            let sig = par_sig.signed_data.signature()?;
            bls_sigs.insert(par_sig.share_idx, sig);
        }

        if (bls_sigs.len() as u64) < self.threshold {
            return Err(SigAggError::InsufficientDistinctSignatures);
        }

        // Convert to u8-indexed map required by the crypto crate.
        #[allow(clippy::cast_possible_truncation)]
        let bls_map: HashMap<u8, [u8; 96]> = bls_sigs
            .iter()
            .map(|(idx, sig)| (*idx as u8, *sig.as_ref()))
            .collect();

        let agg_bytes = BlstImpl
            .threshold_aggregate(&bls_map)
            .map_err(SigAggError::ThresholdAggregate)?;

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
                att.0.validator_index?;
                Some(ps.signed_data.as_ref())
            })
            .unwrap_or_else(|| par_sigs[0].signed_data.as_ref());

        let agg_signed = template.set_signature_boxed(Signature::new(agg_bytes))?;

        (self.verify_fn)(pubkey, agg_signed.as_ref()).await?;

        Ok(agg_signed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls};

    use super::*;
    use crate::{signeddata::SignedDataError, types::Signature as CoreSig};

    fn noop_verify() -> VerifyFn {
        Arc::new(|_, _| Box::pin(async { Ok(()) }))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockSignedData {
        sig: [u8; 96],
    }

    impl SignedData for MockSignedData {
        fn signature(&self) -> std::result::Result<CoreSig, SignedDataError> {
            Ok(CoreSig::new(self.sig))
        }

        fn set_signature(&self, sig: CoreSig) -> std::result::Result<Self, SignedDataError>
        where
            Self: Sized,
        {
            Ok(Self { sig: *sig.as_ref() })
        }

        fn set_signature_boxed(
            &self,
            signature: CoreSig,
        ) -> std::result::Result<Box<dyn SignedData>, SignedDataError> {
            Ok(Box::new(self.set_signature(signature)?))
        }

        fn message_root(&self) -> std::result::Result<[u8; 32], SignedDataError> {
            Ok([0u8; 32])
        }
    }

    fn mock_par_sigs(count: usize, share_idx: u64) -> Vec<ParSignedData> {
        (0..count)
            .map(|_| ParSignedData::new(MockSignedData { sig: [0u8; 96] }, share_idx))
            .collect()
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
            .aggregate(&Duty::new_attester_duty(1.into()), set)
            .await
            .unwrap_err();
        assert!(matches!(err, SigAggError::RequireThresholdSignatures));
        assert_eq!(err.to_string(), "require threshold signatures");
    }

    #[tokio::test]
    async fn aggregate_attester() {
        const THRESHOLD: u64 = 3;
        const PEERS: u8 = 4;

        let tbls = BlstImpl;
        let mut rng = rand::thread_rng();

        let secret = tbls.generate_secret_key(&mut rng).unwrap();
        let pubkey = tbls.secret_to_public_key(&secret).unwrap();
        let shares = tbls
            .threshold_split(&secret, PEERS, u8::try_from(THRESHOLD).unwrap())
            .unwrap();

        let msg = [42u8; 32];

        let mut par_sigs = Vec::new();
        let mut expected_bls: HashMap<u8, [u8; 96]> = HashMap::new();

        for (share_idx, share) in &shares {
            let sig = tbls.sign(share, &msg).unwrap();
            expected_bls.insert(*share_idx, sig);
            par_sigs.push(ParSignedData::new(
                MockSignedData { sig },
                u64::from(*share_idx),
            ));
        }

        let expected_agg = tbls.threshold_aggregate(&expected_bls).unwrap();

        let mut agg = Aggregator::new(THRESHOLD, noop_verify()).unwrap();

        let received: Arc<Mutex<Option<CoreSig>>> = Arc::new(Mutex::new(None));
        let received_clone = received.clone();

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

        agg.aggregate(&Duty::new_attester_duty(1.into()), set)
            .await
            .unwrap();

        let received_sig = received.lock().unwrap().take().unwrap();
        assert_eq!(*received_sig.as_ref(), expected_agg);
    }

    #[tokio::test]
    async fn insufficient_distinct_signatures() {
        // 4 parSigs all with the same share_idx → deduplicates to 1, below threshold 3.
        let agg = Aggregator::new(3, noop_verify()).unwrap();
        let mut set = HashMap::new();
        set.insert(PubKey::new([0u8; 48]), mock_par_sigs(4, 0));
        let err = agg
            .aggregate(&Duty::new_attester_duty(1.into()), set)
            .await
            .unwrap_err();
        assert!(matches!(err, SigAggError::InsufficientDistinctSignatures));
        assert_eq!(
            err.to_string(),
            "number of partial signatures less than threshold"
        );
    }
}
