use blsful::{Bls12381G2Impl, BlsSignatureImpl, PublicKey as BlsPublicKey, SecretKey};

use crate::types::{Error, Index, PUBLIC_KEY_LENGTH, PrivateKey, PublicKey};

/// Function converts a private key from be bytes to a secret key.
pub fn secret_key_from_be_bytes(
    secret_key: &PrivateKey,
) -> Result<SecretKey<Bls12381G2Impl>, Error> {
    let result = SecretKey::<Bls12381G2Impl>::from_be_bytes(secret_key);
    if result.is_none().unwrap_u8() == 1 {
        return Err(Error::FailedToDeserializeSecretKey {
            bls_error: "Invalid secret key bytes".to_string(),
        });
    }
    Ok(result.unwrap())
}

/// Function converts a BLS public key to a Charon public key.
pub fn public_key_from_bls_public_key<T>(public_key: BlsPublicKey<T>) -> Result<PublicKey, Error>
where
    T: BlsSignatureImpl,
{
    let public_key_vec = Vec::from(&public_key);

    if public_key_vec.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidPublicKeyLength {
            expected: PUBLIC_KEY_LENGTH,
            got: public_key_vec.len(),
        });
    }

    let mut public_key = [0u8; PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(&public_key_vec);
    Ok(public_key)
}

/// Function validates a threshold.
pub fn validate_threshold(threshold: Index) -> Result<(), Error> {
    if threshold == 0 {
        return Err(Error::InvalidThreshold {
            expected: 1,
            got: 0,
        });
    }
    Ok(())
}

/// Function converts a vector-like type to a fixed-size byte array.
pub fn vector_like_to_bytes<const N: usize>(
    vector_like: impl Into<Vec<u8>>,
) -> Result<[u8; N], Error> {
    let vector_like_vec = vector_like.into();
    if vector_like_vec.len() != N {
        return Err(Error::InvalidBytesLength {
            expected: N,
            got: vector_like_vec.len(),
        });
    }
    let mut bytes = [0u8; N];
    bytes.copy_from_slice(&vector_like_vec);
    Ok(bytes)
}
