use std::io::{self, Write};

use crate::error::Result;

/// Arguments for the version command.
#[derive(clap::Args)]
pub struct VersionArgs {
    #[arg(
        long,
        help = "Includes detailed module version info and supported protocols."
    )]
    pub verbose: bool,
}

/// Runs the version command.
pub fn run(args: VersionArgs) -> Result<()> {
    run_with_writer(args, &mut io::stdout())
}

/// Runs the version command with a custom writer (used for testing).
fn run_with_writer<W: Write>(args: VersionArgs, writer: &mut W) -> Result<()> {
    let (hash, timestamp) = pluto_core::version::git_commit();
    writeln!(
        writer,
        "{} [git_commit_hash={},git_commit_time={}]",
        *pluto_core::version::VERSION,
        hash,
        timestamp
    )?;

    if !args.verbose {
        return Ok(());
    }

    writeln!(writer, "Package: {}", env!("CARGO_PKG_NAME"))?;
    writeln!(writer, "Dependencies:")?;

    for dependency in pluto_core::version::dependencies() {
        writeln!(writer, "\t{dependency}")?;
    }

    writeln!(writer, "Consensus protocols:")?;
    for protocol in pluto_core::consensus::protocols::protocols() {
        writeln!(writer, "\t{}", protocol)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_version_cmd_default() {
        let mut buf = Vec::new();
        let args = VersionArgs { verbose: false };

        let result = run_with_writer(args, &mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).expect("valid UTF-8 output");

        // Check that output contains git info
        assert!(
            output.contains("git_commit_hash"),
            "Output should contain git_commit_hash"
        );
        assert!(
            output.contains("git_commit_time"),
            "Output should contain git_commit_time"
        );

        // Check that verbose-only content is NOT present
        assert!(
            !output.contains("Package:"),
            "Default output should not contain Package:"
        );

        // Parse the version from output
        // Format: "v1.7.1
        // [git_commit_hash=abc1234,git_commit_time=2024-01-01T00:00:00Z]\n"
        let parts: Vec<&str> = output.split_whitespace().collect();
        assert_eq!(
            parts.len(),
            2,
            "Default output should have exactly 2 space-separated parts"
        );

        // Parse the version string
        let version_str = parts[0];
        let parsed_version = pluto_core::version::SemVer::parse(version_str).expect("valid semver");
        assert_eq!(
            parsed_version,
            *pluto_core::version::VERSION,
            "Parsed version should match VERSION constant"
        );
    }

    #[test]
    fn test_run_version_cmd_verbose() {
        let mut buf = Vec::new();
        let args = VersionArgs { verbose: true };

        let result = run_with_writer(args, &mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).expect("valid UTF-8 output");

        // Check that output contains git info
        assert!(
            output.contains("git_commit_hash"),
            "Output should contain git_commit_hash"
        );
        assert!(
            output.contains("git_commit_time"),
            "Output should contain git_commit_time"
        );

        // Check that verbose content is present
        assert!(
            output.contains("Package:"),
            "Verbose output should contain Package:"
        );
        assert!(
            output.contains("Dependencies:"),
            "Verbose output should contain Dependencies:"
        );
        assert!(
            output.contains("Consensus protocols:"),
            "Verbose output should contain Consensus protocols:"
        );

        // Check that the first protocol is listed
        let protocols = pluto_core::consensus::protocols::protocols();
        assert!(!protocols.is_empty(), "Should have at least one protocol");
        let first_protocol = protocols[0].to_string();
        assert!(
            output.contains(&first_protocol),
            "Verbose output should contain the first protocol: {}",
            first_protocol
        );
    }
}
