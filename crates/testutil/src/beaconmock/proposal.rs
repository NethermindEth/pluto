//! Proposal-preparation recording endpoint used by `BeaconMock`.
//!
//! Charon's Go beaconmock swallows `prepare_beacon_proposer` submissions
//! (testutil/beaconmock/server.go); Pluto instead records them so the
//! app-level fee-recipient subscriber can be asserted against the mock in
//! tests.

use std::sync::{Arc, RwLock};

use pluto_eth2api::ProposalPreparation;
use serde::Deserialize;
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path},
};

use super::{
    defaults::error_response,
    state::{MockState, read_lock, write_lock},
};

/// Priority for the recording route; lower value (higher priority) than the
/// default 200 handler in `defaults.rs`, so submissions are captured instead of
/// silently swallowed.
const PROPOSAL_PREPARATION_PRIORITY: u8 = 100;

/// Records proposal preparations submitted to
/// `/eth/v1/validator/prepare_beacon_proposer`.
#[derive(Debug, Default)]
pub(crate) struct ProposalPreparationStore {
    submissions: RwLock<Vec<ProposalPreparation>>,
}

impl ProposalPreparationStore {
    fn record(&self, preparations: impl IntoIterator<Item = ProposalPreparation>) {
        write_lock(&self.submissions).extend(preparations);
    }

    /// Returns every preparation recorded so far, in submission order.
    pub(crate) fn submissions(&self) -> Vec<ProposalPreparation> {
        read_lock(&self.submissions).clone()
    }
}

/// Wire representation of a single `prepare_beacon_proposer` body item.
#[derive(Debug, Deserialize)]
struct ProposalPreparationItem {
    validator_index: String,
    fee_recipient: String,
}

/// Mounts the recording `prepare_beacon_proposer` handler on `server`.
pub(crate) async fn mount(server: &MockServer, state: Arc<MockState>) {
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(move |request: &Request| response(&state, request))
        .with_priority(PROPOSAL_PREPARATION_PRIORITY)
        .mount(server)
        .await;
}

fn response(state: &MockState, request: &Request) -> ResponseTemplate {
    match parse_body(&request.body) {
        Ok(preparations) => {
            state.proposal_preparation_store.record(preparations);
            ResponseTemplate::new(200)
        }
        Err(message) => error_response(400, message),
    }
}

fn parse_body(body: &[u8]) -> Result<Vec<ProposalPreparation>, &'static str> {
    let items: Vec<ProposalPreparationItem> =
        serde_json::from_slice(body).map_err(|_| "invalid prepare_beacon_proposer body")?;

    items
        .into_iter()
        .map(|item| {
            let validator_index = item
                .validator_index
                .parse()
                .map_err(|_| "invalid validator_index")?;
            let fee_recipient = parse_execution_address(&item.fee_recipient)?;
            Ok(ProposalPreparation {
                validator_index,
                fee_recipient,
            })
        })
        .collect()
}

fn parse_execution_address(value: &str) -> Result<[u8; 20], &'static str> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(stripped).map_err(|_| "invalid fee_recipient hex")?;
    bytes.try_into().map_err(|_| "invalid fee_recipient length")
}

#[cfg(test)]
mod tests {
    use crate::beaconmock::BeaconMock;
    use pluto_eth2api::ProposalPreparation;
    use serde_json::json;

    #[tokio::test]
    async fn records_submitted_preparations() {
        let mock = BeaconMock::builder()
            .build()
            .await
            .expect("build beacon mock");

        let preparations = vec![
            ProposalPreparation {
                validator_index: 1,
                fee_recipient: [0x11; 20],
            },
            ProposalPreparation {
                validator_index: 7,
                fee_recipient: [0x22; 20],
            },
        ];

        mock.client()
            .submit_proposal_preparations(&preparations)
            .await
            .expect("submit succeeds");

        assert_eq!(mock.state().proposal_preparations(), preparations);
    }

    #[tokio::test]
    async fn accumulates_across_submissions() {
        let mock = BeaconMock::builder()
            .build()
            .await
            .expect("build beacon mock");

        let first = ProposalPreparation {
            validator_index: 1,
            fee_recipient: [0x11; 20],
        };
        let second = ProposalPreparation {
            validator_index: 2,
            fee_recipient: [0x22; 20],
        };

        mock.client()
            .submit_proposal_preparations(std::slice::from_ref(&first))
            .await
            .expect("first submit succeeds");
        mock.client()
            .submit_proposal_preparations(std::slice::from_ref(&second))
            .await
            .expect("second submit succeeds");

        assert_eq!(mock.state().proposal_preparations(), vec![first, second]);
    }

    #[tokio::test]
    async fn rejects_invalid_body() {
        let mock = BeaconMock::builder()
            .build()
            .await
            .expect("build beacon mock");

        let response = reqwest::Client::new()
            .post(format!(
                "{}/eth/v1/validator/prepare_beacon_proposer",
                mock.uri()
            ))
            .json(&json!([{ "validator_index": "abc", "fee_recipient": "0x00" }]))
            .send()
            .await
            .expect("send");

        assert_eq!(response.status(), 400);
        assert!(mock.state().proposal_preparations().is_empty());
    }
}
