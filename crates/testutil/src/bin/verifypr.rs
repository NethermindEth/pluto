//! Command `verifypr` verifies a GitHub pull request against the contribution
//! template.
//!
//! The PR is read as JSON from the `GITHUB_PR` env variable.

use std::{io, process::ExitCode};

use pluto_testutil::verifypr::verify;

fn main() -> ExitCode {
    tracing_subscriber::fmt().with_writer(io::stderr).init();

    if let Err(err) = verify() {
        tracing::error!(%err, "❌ Verification failed");

        return ExitCode::FAILURE;
    }

    tracing::info!("✅ Verification success");

    ExitCode::SUCCESS
}
