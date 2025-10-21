use std::collections::HashMap;

use blsful::{
    AggregateSignature, Bls12381G2Impl, MultiSignature, PublicKey as BlsPublicKey, SecretKey,
    SecretKeyShare, Signature as BlsSignature, SignatureSchemes, SignatureShare,
    vsss_rs::elliptic_curve::rand_core::{CryptoRng, RngCore},
};

use crate::tbls::{Error, PrivateKey, PublicKey, Signature, Tbls};

/// Herumi is an Implementation with Herumi-specific inner logic.
pub struct Herumi {}

impl Herumi {
    /// Create a new Herumi instance.
    pub fn new() -> Self {
        Self {}
    }
}

impl Tbls for Herumi {
    // todo: this is not aligned with the original implementation
    fn generate_secret_key(&self, mut rng: impl RngCore + CryptoRng) -> Result<PrivateKey, Error> {
        let result: SecretKey<Bls12381G2Impl> = SecretKey::random(&mut rng);
        Ok(result.to_be_bytes())
    }

    fn generate_insecure_secret(
        &self,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<PrivateKey, Error> {
        unimplemented!()
    }

    fn secret_to_public_key(&self, secret_key: &PrivateKey) -> Result<PublicKey, Error> {
        let result = SecretKey::<Bls12381G2Impl>::from_be_bytes(secret_key);
        if result.is_none().unwrap_u8() == 1 {
            return Err(Error::FailedToDeserializeSecretKey);
        }
        let secret_key = result.unwrap();
        let public_key = secret_key.public_key();

        let public_key_vec = Vec::from(&public_key);

        if public_key_vec.len() != 48 {
            return Err(Error::InvalidPublicKeyLength);
        }

        let mut public_key = [0u8; 48];
        public_key.copy_from_slice(&public_key_vec);
        Ok(public_key)
    }

    fn threshold_split_insecure(
        &self,
        secret_key: &PrivateKey,
        total: u64,
        threshold: u64,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<HashMap<u64, PrivateKey>, Error> {
        let result = SecretKey::<Bls12381G2Impl>::from_be_bytes(secret_key);
        if result.is_none().unwrap_u8() == 1 {
            return Err(Error::FailedToDeserializeSecretKey);
        }
        let secret_key = result.unwrap();
        let shares = secret_key
            .split_with_rng(threshold as usize, total as usize, &mut rng)
            .unwrap();

        let mut shares_map = HashMap::new();
        for (i, share) in shares.iter().enumerate() {
            let share_vec = Vec::from(share.as_raw_value());
            let mut share_secret_key = [0u8; 32];
            share_secret_key.copy_from_slice(&share_vec);
            shares_map.insert(i as u64, share_secret_key);
        }

        Ok(shares_map)
    }

    fn threshold_split(
        &self,
        secret_key: &PrivateKey,
        total: u64,
        threshold: u64,
    ) -> Result<HashMap<u64, PrivateKey>, Error> {
        let result = SecretKey::<Bls12381G2Impl>::from_be_bytes(secret_key);
        if result.is_none().unwrap_u8() == 1 {
            return Err(Error::FailedToDeserializeSecretKey);
        }
        let secret_key = result.unwrap();
        let shares = secret_key
            .split(threshold as usize, total as usize)
            .unwrap();

        let mut shares_map = HashMap::new();
        for (i, share) in shares.iter().enumerate() {
            let share_vec = Vec::from(share.as_raw_value());
            let mut share_secret_key = [0u8; 32];
            share_secret_key.copy_from_slice(&share_vec);
            shares_map.insert(i as u64, share_secret_key);
        }

        Ok(shares_map)
    }

    fn recover_secret(&self, shares: HashMap<u64, PrivateKey>) -> Result<PrivateKey, Error> {
        let mut shares_vec = Vec::new();
        for (_, share) in shares.iter() {
            match SecretKeyShare::<Bls12381G2Impl>::try_from(share.as_slice()) {
                Ok(share) => shares_vec.push(share),
                Err(_) => return Err(Error::FailedToDeserializeSecretKey),
            }
        }
        let secret_key = SecretKey::<Bls12381G2Impl>::combine(&shares_vec).unwrap();
        Ok(secret_key.to_be_bytes())
    }

    fn aggregate(&self, signatures: Vec<Signature>) -> Result<Signature, Error> {
        let mut signatures_vec = Vec::new();

        for signature in signatures {
            match BlsSignature::<Bls12381G2Impl>::try_from(signature.as_slice()) {
                Ok(signature) => signatures_vec.push(signature),
                Err(_) => return Err(Error::FailedToDeserializeSignatureKey),
            }
        }

        let signature = blsful::AggregateSignature::from_signatures(&signatures_vec).unwrap();

        let signature_vec = Vec::from(signature);
        let mut signature = [0u8; 96];
        signature.copy_from_slice(&signature_vec);
        Ok(signature)
    }

    fn threshold_aggregate(
        &self,
        partial_signatures_by_idx: HashMap<u64, Signature>,
    ) -> Result<Signature, Error> {
        let mut partial_signatures_vec = Vec::with_capacity(partial_signatures_by_idx.len());

        for (_, signature) in partial_signatures_by_idx.iter() {
            match SignatureShare::<Bls12381G2Impl>::try_from(signature.as_slice()) {
                Ok(signature) => partial_signatures_vec.push(signature),
                Err(_) => return Err(Error::FailedToDeserializeSignatureKey),
            }
        }

        let signature = BlsSignature::from_shares(&partial_signatures_vec)
            .map_err(|_| Error::FailedToDeserializeSignatureKey)?;
        let signature_vec = Vec::from(signature);

        let mut signature = [0u8; 96];
        signature.copy_from_slice(&signature_vec);
        Ok(signature)
    }

    fn verify(
        &self,
        public_key: &PublicKey,
        data: &[u8],
        raw_signature: &Signature,
    ) -> Result<(), Error> {
        let public_key = BlsPublicKey::<Bls12381G2Impl>::try_from(public_key.as_slice())
            .map_err(|_| Error::FailedToDeserializePublicKey)?;
        let signature = BlsSignature::<Bls12381G2Impl>::try_from(raw_signature.as_slice())
            .map_err(|_| Error::FailedToDeserializeSignatureKey)?;
        signature
            .verify(&public_key, data)
            .map_err(|_| Error::FailedToVerifySignature)
    }

    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Signature, Error> {
        let private_key = SecretKey::<Bls12381G2Impl>::from_be_bytes(private_key);
        if private_key.is_none().unwrap_u8() == 1 {
            return Err(Error::FailedToDeserializeSecretKey);
        }
        let private_key = private_key.unwrap();
        let signature = private_key
            .sign(SignatureSchemes::Basic, data)
            .map_err(|_| Error::FailedToGenerateSignature)?;
        let signature_vec = Vec::from(signature);
        let mut signature = [0u8; 96];
        signature.copy_from_slice(&signature_vec);
        Ok(signature)
    }

    fn verify_aggregate(
        &self,
        public_keys: Vec<PublicKey>,
        signature: Signature,
        data: &[u8],
    ) -> Result<(), Error> {
        let signature = AggregateSignature::try_from(signature.as_slice())
            .map_err(|_| Error::FailedToDeserializeSignatureKey)?;
        let public_keys = public_keys
            .iter()
            .map(|public_key| {
                BlsPublicKey::<Bls12381G2Impl>::try_from(public_key.as_slice())
                    .map_err(|_| Error::FailedToDeserializePublicKey)
            })
            .collect::<Result<Vec<BlsPublicKey<Bls12381G2Impl>>, Error>>()?;
        let public_keys = public_keys
            .iter()
            .map(|public_key| (*public_key, data))
            .collect::<Vec<_>>();
        signature
            .verify(&public_keys)
            .map_err(|_| Error::FailedToVerifySignature)
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
    use blsful::vsss_rs::elliptic_curve;

    use super::*;

    #[test]
    fn test_secret_to_public_key() {
        let herumi = Herumi::new();
        let sk = herumi
            .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
            .unwrap();
        let pk = herumi.secret_to_public_key(&sk).unwrap();
        println!("{:?}", pk);
    }
}
