//! Active-validator lookup against the beacon node.
//!
//! Mirrors Go's `eth2wrap.Client.ActiveValidators` (a thin filter over
//! `/eth/v1/beacon/states/head/validators`). Local to this crate so the
//! validator mock does not depend on `pluto-app`, which itself dev-depends on
//! `pluto-testutil`.

use std::collections::HashMap;

use pluto_eth2api::{
    EthBeaconNodeApiClient, EthBeaconNodeApiClientError, GetStateValidatorsResponseResponse,
    PostStateValidatorsRequest, PostStateValidatorsResponse, ValidatorRequestBody,
    spec::phase0::{BLSPubKey, ValidatorIndex},
};

use super::error::{Error, Result};

/// Active validators indexed by [`ValidatorIndex`].
///
/// Constructed by [`active_validators`]; the mock does not cache, callers
/// typically query once per slot like the Go implementation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveValidators(HashMap<ValidatorIndex, BLSPubKey>);

impl ActiveValidators {
    /// Indices of every active validator. Order is unspecified.
    pub fn indices(&self) -> impl Iterator<Item = ValidatorIndex> + '_ {
        self.0.keys().copied()
    }

    /// Public keys of every active validator. Order is unspecified.
    pub fn pubkeys(&self) -> impl Iterator<Item = &BLSPubKey> + '_ {
        self.0.values()
    }

    /// Public key for `index`, if present.
    #[must_use]
    pub fn get(&self, index: ValidatorIndex) -> Option<&BLSPubKey> {
        self.0.get(&index)
    }

    /// Number of active validators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if no validators are active.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<I> FromIterator<I> for ActiveValidators
where
    I: Into<(ValidatorIndex, BLSPubKey)>,
{
    fn from_iter<T: IntoIterator<Item = I>>(iter: T) -> Self {
        Self(iter.into_iter().map(Into::into).collect())
    }
}

/// Fetches active validators from the beacon node and returns them as a map.
///
/// Mirrors Go's `eth2Cl.ActiveValidators(ctx)`: queries `head`, filters by
/// status, drops malformed entries.
pub async fn active_validators(client: &EthBeaconNodeApiClient) -> Result<ActiveValidators> {
    let request = PostStateValidatorsRequest {
        path: pluto_eth2api::PostStateValidatorsRequestPath {
            state_id: "head".to_string(),
        },
        body: ValidatorRequestBody {
            ids: None,
            statuses: None,
        },
    };

    let response = client
        .post_state_validators(request)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)
        .and_then(|r| match r {
            PostStateValidatorsResponse::Ok(ok) => Ok(ok),
            _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
        })?;

    Ok(filter_active(response))
}

fn filter_active(response: GetStateValidatorsResponseResponse) -> ActiveValidators {
    let mut map = HashMap::new();
    for datum in response.data {
        if !datum.status.is_active() {
            continue;
        }
        let Ok(index) = datum.index.parse::<ValidatorIndex>() else {
            continue;
        };
        let Ok(pubkey) = parse_bls_pubkey(&datum.validator.pubkey) else {
            continue;
        };
        map.insert(index, pubkey);
    }
    ActiveValidators(map)
}

fn parse_bls_pubkey(s: &str) -> Result<BLSPubKey> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|e| Error::Malformed(e.to_string()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed(format!("pubkey length {} != 48", bytes.len())))
}
