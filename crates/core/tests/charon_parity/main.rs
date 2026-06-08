//! Charon-parity fixture-replay harness — entry point.
//!
//! Walks `crates/core/testdata/charon-parity/**/*.json`, dispatches
//! each fixture into the matching `validatorapi::Handler` method, and
//! records the outcome in a [`ParitySummary`]. Status-aware:
//!
//! - `implemented` fixtures must match their `expected` body exactly.
//! - `unimplemented` fixtures must panic with an `unimplemented!()` payload —
//!   confirming the stub is still in place. If the handler stops panicking, the
//!   run **fails** as a "graduation candidate" prompting the porter to upgrade
//!   the fixture.
//! - `partial` fixtures are logged but never fail (use sparingly for known,
//!   tracked divergences).
//!
//! Author guide for new fixtures:
//! `crates/core/testdata/charon-parity/README.md`.

mod fixture;
mod harness;

use std::path::PathBuf;

use harness::{ParitySummary, evaluate, load_all};

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("charon-parity")
}

#[tokio::test]
async fn charon_parity() {
    let root = fixtures_root();
    let fixtures = load_all(&root);
    assert!(
        !fixtures.is_empty(),
        "no fixtures found under {}",
        root.display()
    );

    let mut summary = ParitySummary::default();
    for (path, fixture) in &fixtures {
        // Each fixture's result is folded into `summary`; per-fixture
        // failures are accumulated, not propagated, so the summary
        // covers the whole set before the final assertion fires.
        let _ = evaluate(path, fixture, &mut summary).await;
    }

    println!("{summary}");
    if !summary.failures.is_empty() {
        let detail = summary.failures.join("\n\n");
        panic!("Charon-parity harness failures:\n\n{detail}");
    }
}
