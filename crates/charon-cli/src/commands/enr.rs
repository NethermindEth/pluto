//! ENR command implementation.
//!
//! This module implements the `pluto enr` command, which prints the Ethereum
//! Node Record (ENR) that identifies this client to its peers.

use std::{
    io::{self, Write},
    path::PathBuf,
};

use charon_eth2::enr::Record;
use charon_k1util;
use charon_p2p::k1;
use k256::SecretKey;

use crate::error::{CliError, Result};

/// Arguments for the ENR command.
#[derive(clap::Args)]
pub struct EnrArgs {
    #[arg(
        long = "data-dir",
        env = "CHARON_DATA_DIR",
        default_value = ".charon",
        help = "The directory where pluto will store all its internal data."
    )]
    pub data_dir: PathBuf,

    #[arg(long, help = "Prints the expanded form of ENR.")]
    pub verbose: bool,
}

/// Loads the p2pkey from disk and prints the ENR for the provided config.
pub fn run(args: EnrArgs) -> Result<()> {
    let mut writer = io::stdout();

    let key = match k1::load_priv_key(&args.data_dir) {
        Ok(key) => key,
        Err(k1::K1Error::K1UtilError(charon_k1util::K1UtilError::FailedToReadFile(io_err)))
            if io_err.kind() == std::io::ErrorKind::NotFound =>
        {
            // File not found
            let enr_path = k1::key_path(&args.data_dir);
            return Err(CliError::PrivateKeyNotFound { enr_path });
        }
        Err(e) => {
            return Err(CliError::KeyLoadError(e));
        }
    };

    let record = Record::new(key.clone(), vec![])?;

    writeln!(writer, "{}", record)?;

    if args.verbose {
        write_expanded_enr(&mut writer, &record, &key)?;
    }

    Ok(())
}

/// Writes the expanded form of ENR to the terminal
fn write_expanded_enr(w: &mut dyn Write, record: &Record, privkey: &SecretKey) -> Result<()> {
    writeln!(w)?;
    writeln!(
        w,
        "***************** Decoded ENR (see https://enr-viewer.com/ for additional fields) **********************"
    )?;

    let pubkey_bytes = privkey.public_key().to_sec1_bytes();
    writeln!(w, "secp256k1 pubkey: {}", format_hex(&pubkey_bytes))?;
    writeln!(w, "signature: {}", format_hex(&record.signature))?;

    writeln!(
        w,
        "********************************************************************************************************"
    )?;
    writeln!(w)?;

    Ok(())
}

/// Formats bytes as hex with 0x prefix
fn format_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
