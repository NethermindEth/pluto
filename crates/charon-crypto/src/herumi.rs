use std::{collections::HashMap, sync::Once};

use blst::min_pk::SecretKey;
use rand::Rng;

use blst::min_pk::{
    PublicKey as BlstPublicKey, SecretKey as BlstSecretKey,
};

use crate::tbls::{Error, PrivateKey, PublicKey, Tbls, Signature};

const INIT_ONCE: Once = Once::new();

/// Herumi is an Implementation with Herumi-specific inner logic.
pub struct Herumi {}

impl Herumi {
    /// Create a new Herumi instance.
    pub fn new() -> Self {
        Self {}
    }

    /// Initialize the Herumi instance.
    pub fn init() {
        INIT_ONCE.call_once(|| {});
    }
}

fn generate_insecure_secret(rng: &mut impl Rng) -> Result<SecretKey, Error> {
    for _ in 0..100 {
        let mut ikm = [0u8; 32];
        rng.fill(&mut ikm);
        let sk = SecretKey::deserialize(&ikm);
        if sk.is_ok() {
            return Ok(sk.unwrap());
        }
    }
    Err(Error::InvalidSecretKeyLength)
}

impl Tbls for Herumi {
    // todo: this is not aligned with the original implementation
    fn generate_secret_key(&self) -> Result<PrivateKey, Error> {
        let mut ikm = [0u8; 32];
        rand::rng().fill(&mut ikm);
        let sk = SecretKey::key_gen(&ikm, &[]).map_err(|_| Error::InvalidSecretKeyLength)?;
        Ok(sk.serialize())
    }

    fn generate_insecure_secret(&self, rng: &mut impl Rng) -> Result<PrivateKey, Error> {
        for _ in 0..100 {
            let mut ikm = [0u8; 32];
            rng.fill(&mut ikm);
            let sk = SecretKey::deserialize(&ikm);

            if sk.is_ok() {
                return Ok(sk.unwrap().serialize());
            }
        }
        Err(Error::InvalidSecretKeyLength)
    }

    fn secret_to_public_key(&self, secret_key: &PrivateKey) -> Result<PublicKey, Error> {
        let sk =
            SecretKey::deserialize(secret_key).map_err(|_| Error::FailedToDeserializeSecretKey)?;
        let pk = sk.sk_to_pk();
        Ok(pk.to_bytes())
    }

    fn threshold_split_insecure(
        &self,
        secret_key: &PrivateKey,
        total: u64,
        threshold: u64,
        rng: &mut impl Rng,
    ) -> Result<HashMap<u64, PrivateKey>, Error> {
        if threshold <= 1 {
            return Err(Error::InvalidThreshold);
        }
        let sk = SecretKey::deserialize(secret_key).map_err(|_| Error::FailedToDeserializeSecretKey)?;


        let mut poly: HashMap<u64, PrivateKey> = HashMap::new();

        // Initialize threshold amount of points
        for i in 1..threshold {
            let secret = generate_insecure_secret(rng)?;

            poly.insert(i, secret.serialize());
        }

        Ok(poly)
    }

    fn threshold_split(
        &self,
        _secret_key: &PrivateKey,
        _total: u64,
        _threshold: u64,
    ) -> Result<HashMap<u64, PrivateKey>, Error> {
        unimplemented!()
    }

    fn recover_secret(&self, _shares: HashMap<u64, PrivateKey>) -> Result<PrivateKey, Error> {
        unimplemented!()
    }

    fn aggregate(&self, _signatures: Vec<Signature>) -> Result<Signature, Error> {
        unimplemented!()
    }

    fn threshold_aggregate(
        &self,
        _partial_signatures_by_idx: HashMap<u64, Signature>,
    ) -> Result<Signature, Error> {
        unimplemented!()
    }

    fn verify(
        &self,
        _public_key: &PublicKey,
        _data: &[u8],
        _raw_signature: &Signature,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    fn sign(&self, _private_key: &PrivateKey, _data: &[u8]) -> Result<Signature, Error> {
        unimplemented!()
    }

    fn verify_aggregate(
        &self,
        _public_keys: Vec<PublicKey>,
        _signature: Signature,
        _data: &[u8],
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

/// Testing functions
impl Herumi {
    /// GenerateInsecureKey generates a key that is not cryptographically secure
    /// using the provided random number generator. This is useful for
    /// testing.
    pub(crate) fn generate_insecure_key(&self) -> Result<PrivateKey, Error> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secret_key() {
        let herumi = Herumi::new();
        let sk = herumi.generate_secret_key().unwrap();
        println!("{:?}", sk);
    }

    #[test]
    fn test_generate_insecure_secret() {
        let herumi = Herumi::new();
        let sk = herumi.generate_insecure_secret(&mut rand::rng()).unwrap();
        println!("{:?}", sk);
    }
}
