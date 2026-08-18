//! Obol API fee-recipient (builder registration) endpoints.
//!
//! Port of `charon/app/obolapi/feerecipient.go` and `feerecipient_model.go`.
//!
//! Two endpoints:
//!
//! * `POST /fee_recipient/partial/{lock_hash}/{share_index}` — an operator
//!   submits its partial signature over a builder registration.
//! * `POST /fee_recipient/{lock_hash}` — a node fetches the cluster's
//!   registrations, each carrying either a quorum of partial signatures (which
//!   the caller aggregates) or fewer.

use pluto_crypto::types::Signature;
use pluto_eth2api::v1::ValidatorRegistration;
use serde::{Deserialize, Serialize};

use super::{
    client::Client,
    error::{Error, Result},
};

/// Length of a BLS signature in bytes.
const SIGNATURE_LEN: usize = 96;

/// Cap on the fetch response body. A cluster registration set is a few hundred
/// bytes per validator; 16 MiB covers far more validators than any real
/// cluster while still bounding a hostile response.
const MAX_FETCH_BODY: usize = 16 * 1024 * 1024;

/// A partial builder registration: a registration message plus this operator's
/// partial BLS signature over it.
///
/// The signature is a `0x`-prefixed hex string on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialRegistration {
    /// The registration being signed.
    pub message: ValidatorRegistration,
    /// This operator's partial signature.
    #[serde(with = "signature_hex")]
    pub signature: Signature,
}

/// Request body for `POST /fee_recipient/partial/{lock_hash}/{share_index}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialFeeRecipientRequest {
    /// The partial registrations being submitted.
    pub partial_registrations: Vec<PartialRegistration>,
}

/// Request body for `POST /fee_recipient/{lock_hash}`.
///
/// An empty `pubkeys` list requests every validator in the cluster.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeeRecipientFetchRequest {
    /// Optional filter; empty means "all validators".
    pub pubkeys: Vec<String>,
}

/// One operator's partial signature, tagged with its share index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRecipientPartialSig {
    /// 1-indexed share index of the operator that produced the signature.
    pub share_index: i64,
    /// The partial signature.
    #[serde(with = "signature_hex")]
    pub signature: Signature,
}

/// A group of partial signatures over one registration message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRecipientBuilderRegistration {
    /// The registration all the partial signatures cover.
    pub message: ValidatorRegistration,
    /// Partial signatures collected so far.
    pub partial_signatures: Vec<FeeRecipientPartialSig>,
    /// Whether [`Self::partial_signatures`] meets the cluster threshold, i.e.
    /// whether the group can be aggregated into a usable full signature.
    pub quorum: bool,
}

/// Per-validator entry in the fetch response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRecipientValidator {
    /// `0x`-prefixed validator group public key.
    pub pubkey: String,
    /// Registration groups known for this validator, newest last.
    pub builder_registrations: Vec<FeeRecipientBuilderRegistration>,
}

/// Response body for `POST /fee_recipient/{lock_hash}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRecipientFetchResponse {
    /// One entry per validator the API knows about.
    pub validators: Vec<FeeRecipientValidator>,
}

/// Serde for a BLS signature as a `0x`-prefixed hex string, matching Go's
/// `fmt.Sprintf("%#x", sig)` / `from0x(s, 96)`.
mod signature_hex {
    use pluto_crypto::types::Signature;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use super::SIGNATURE_LEN;

    pub(super) fn serialize<S: Serializer>(
        signature: &Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{}", hex::encode(signature)))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Signature, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let stripped = raw.strip_prefix("0x").unwrap_or(&raw);
        let bytes = hex::decode(stripped).map_err(D::Error::custom)?;

        bytes.try_into().map_err(|bytes: Vec<u8>| {
            D::Error::custom(format!(
                "signature must be {SIGNATURE_LEN} bytes, got {}",
                bytes.len()
            ))
        })
    }
}

/// Returns the partial fee-recipient submission URL for a lock hash and share.
fn submit_partial_fee_recipients_url(lock_hash: &str, share_index: u64) -> String {
    format!("/fee_recipient/partial/{lock_hash}/{share_index}")
}

/// Returns the fee-recipient fetch URL for a lock hash.
fn fetch_fee_recipients_url(lock_hash: &str) -> String {
    format!("/fee_recipient/{lock_hash}")
}

impl Client {
    /// Submits this operator's partial builder registrations for the cluster.
    pub async fn post_partial_fee_recipients(
        &self,
        lock_hash: &[u8],
        share_index: u64,
        partial_registrations: Vec<PartialRegistration>,
    ) -> Result<()> {
        let path = submit_partial_fee_recipients_url(&to_0x_hex(lock_hash), share_index);
        let url = self.build_url(&path)?;
        let body = serde_json::to_vec(&PartialFeeRecipientRequest {
            partial_registrations,
        })?;

        self.http_post(url, body, None).await
    }

    /// Fetches the cluster's builder registrations.
    ///
    /// An empty `pubkeys` fetches every validator. A cluster the API has never
    /// seen a registration for yields an empty response rather than an error,
    /// matching Charon: that is the normal state before any operator has
    /// submitted, not a failure.
    pub async fn post_fee_recipients_fetch(
        &self,
        lock_hash: &[u8],
        pubkeys: Vec<String>,
    ) -> Result<FeeRecipientFetchResponse> {
        let path = fetch_fee_recipients_url(&to_0x_hex(lock_hash));
        let url = self.build_url(&path)?;
        let body = serde_json::to_vec(&FeeRecipientFetchRequest { pubkeys })?;

        match self.http_post_json(url, body, MAX_FETCH_BODY).await {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            // The API returns 404 both for "nothing submitted yet" (benign)
            // and for "this cluster is unknown" (an operator error worth a
            // clear message).
            Err(Error::HttpError { status, body, .. })
                if status == reqwest::StatusCode::NOT_FOUND =>
            {
                if body.contains("no partial registrations found") {
                    Ok(FeeRecipientFetchResponse::default())
                } else if body.contains("lock not found") {
                    Err(Error::UnknownCluster)
                } else {
                    Err(Error::HttpError {
                        method: reqwest::Method::POST,
                        status,
                        body,
                    })
                }
            }
            Err(err) => Err(err),
        }
    }
}

/// Formats bytes as a `0x`-prefixed lowercase hex string.
fn to_0x_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_match_charon() {
        assert_eq!(
            submit_partial_fee_recipients_url("0xabcd1234", 3),
            "/fee_recipient/partial/0xabcd1234/3",
        );
        assert_eq!(
            fetch_fee_recipients_url("0xabcd1234"),
            "/fee_recipient/0xabcd1234",
        );
    }

    /// The wire shape must match Charon's DTOs exactly: snake_case field names
    /// and `0x`-prefixed signatures.
    #[test]
    fn partial_signature_round_trips_as_0x_hex() {
        let json = serde_json::json!({
            "share_index": 2,
            "signature": format!("0x{}", "ab".repeat(SIGNATURE_LEN)),
        });

        let parsed: FeeRecipientPartialSig = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(parsed.share_index, 2);
        assert_eq!(parsed.signature, [0xab; SIGNATURE_LEN]);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), json);
    }

    #[test]
    fn wrong_length_signature_is_rejected() {
        let json = serde_json::json!({
            "share_index": 1,
            "signature": "0xabcd",
        });

        let err = serde_json::from_value::<FeeRecipientPartialSig>(json).unwrap_err();
        assert!(err.to_string().contains("must be 96 bytes"), "{err}");
    }

    #[test]
    fn fetch_response_parses_charon_shape() {
        let json = serde_json::json!({
            "validators": [{
                "pubkey": format!("0x{}", "11".repeat(48)),
                "builder_registrations": [{
                    "message": {
                        "fee_recipient": format!("0x{}", "22".repeat(20)),
                        "gas_limit": "30000000",
                        "timestamp": "1616508000",
                        "pubkey": format!("0x{}", "11".repeat(48)),
                    },
                    "partial_signatures": [
                        { "share_index": 1, "signature": format!("0x{}", "00".repeat(96)) },
                    ],
                    "quorum": false,
                }],
            }],
        });

        let parsed: FeeRecipientFetchResponse = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.validators.len(), 1);
        let registration = &parsed.validators[0].builder_registrations[0];
        assert!(!registration.quorum);
        assert_eq!(registration.message.gas_limit, 30_000_000);
        assert_eq!(registration.partial_signatures.len(), 1);
    }

    /// An empty body is the "no validators yet" case and must parse, not error.
    #[test]
    fn empty_fetch_response_parses() {
        let parsed: FeeRecipientFetchResponse =
            serde_json::from_value(serde_json::json!({ "validators": [] })).unwrap();
        assert!(parsed.validators.is_empty());
    }
}
