use std::io::{self, Write};

use crate::error::Result;

/// Arguments for the version command.
#[derive(clap::Args)]
pub struct VersionArgs {
    /// Includes detailed module version info and supported protocols.
    #[arg(long, short = 'v')]
    pub verbose: bool,
}

/// Runs the version command.
pub fn run(args: VersionArgs) -> Result<()> {
    let mut writer = io::stdout();

    let (hash, timestamp) = charon_core::version::git_commit();
    writeln!(
        writer,
        "{} [git_commit_hash={},git_commit_time={}]",
        *charon_core::version::VERSION,
        hash,
        timestamp
    )?;

    if !args.verbose {
        return Ok(());
    }

    writeln!(writer, "Package: {}", env!("CARGO_PKG_NAME"))?;
    writeln!(writer, "Dependencies:")?;

    for dependency in charon_core::version::dependencies() {
        writeln!(writer, "\t{dependency}")?;
    }

    writeln!(writer, "Consensus protocols:")?;
    for protocol in charon_core::consensus::protocols::protocols() {
        writeln!(writer, "\t{}", protocol)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_output() {
        let args = VersionArgs { verbose: false };
        let result = run(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_version_verbose_output() {
        let args = VersionArgs { verbose: true };
        let result = run(args);
        assert!(result.is_ok());
    }
}
