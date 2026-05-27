//! Pubkey-keyed BLS signer for the validator mock.
//!
//! Mirrors Go's `SignFunc = func(pubkey, data) ([]byte, error)` plus
//! `NewSigner` (`charon/testutil/validatormock/propose.go`). Tests substitute a
//! stub by implementing [`Sign`] directly; production code wraps real BLS
//! secrets via [`Signer::new`].

use std::{collections::HashMap, sync::Arc};

use pluto_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    tblsconv::{pubkey_to_eth2, sig_to_eth2},
    types::PrivateKey,
};
use pluto_eth2api::spec::phase0::{BLSPubKey, BLSSignature};

use super::error::SignError;

/// Trait implemented by anything that can produce a BLS signature for a known
/// public key.
///
/// The trait is `Send + Sync + 'static` so signer handles can be stored on
/// long-lived state owned by the duty scheduler and shared across tasks.
pub trait Sign: Send + Sync + std::fmt::Debug + 'static {
    /// Sign `data` with the secret share registered for `pubkey`.
    fn sign(&self, pubkey: &BLSPubKey, data: &[u8]) -> Result<BLSSignature, SignError>;
}

/// Shared handle to a [`Sign`] implementation. Cheap to clone, stored on every
/// component that needs to sign.
pub type SignFunc = Arc<dyn Sign>;

/// Concrete BLS signer backed by [`BlstImpl`]. Registers a set of secrets by
/// their derived eth2 public key.
#[derive(Debug, Clone)]
pub struct Signer {
    secrets: HashMap<BLSPubKey, PrivateKey>,
}

impl Signer {
    /// Builds a [`Signer`] from `secrets`, deriving each public key with
    /// [`BlstImpl`]. Fails fast if any secret is rejected by the BLS backend.
    pub fn new(secrets: &[PrivateKey]) -> Result<Self, SignError> {
        let tbls = BlstImpl;
        let mut map = HashMap::with_capacity(secrets.len());
        for secret in secrets {
            let pk = tbls.secret_to_public_key(secret)?;
            map.insert(pubkey_to_eth2(pk), *secret);
        }
        Ok(Self { secrets: map })
    }

    /// Convenience constructor returning the [`SignFunc`] handle directly.
    pub fn arc(secrets: &[PrivateKey]) -> Result<SignFunc, SignError> {
        Ok(Arc::new(Self::new(secrets)?))
    }
}

impl Sign for Signer {
    fn sign(&self, pubkey: &BLSPubKey, data: &[u8]) -> Result<BLSSignature, SignError> {
        let secret = self.secrets.get(pubkey).ok_or(SignError::UnknownPubkey)?;
        let sig = BlstImpl.sign(secret, data)?;
        Ok(sig_to_eth2(sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn deterministic_secret(seed: u8) -> PrivateKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        let rng = StdRng::from_seed(bytes);
        BlstImpl.generate_insecure_secret(rng).expect("generate")
    }

    #[test]
    fn round_trip_known_pubkey() {
        let secret = deterministic_secret(1);
        let pubkey = pubkey_to_eth2(
            BlstImpl
                .secret_to_public_key(&secret)
                .expect("derive pubkey"),
        );

        let signer = Signer::new(&[secret]).expect("build signer");
        let sig = signer.sign(&pubkey, b"msg").expect("sign");
        assert_ne!(sig, [0u8; 96]);
    }

    #[test]
    fn unknown_pubkey_errors() {
        let signer = Signer::new(&[deterministic_secret(2)]).expect("build signer");
        let err = signer.sign(&[0u8; 48], b"msg").expect_err("must fail");
        assert!(matches!(err, SignError::UnknownPubkey));
    }
}
