//! Create ENR command implementation.
//!
//! This module implements the `pluto create enr` command, which generates a new
//! Ethereum Node Record (ENR) private key and stores it securely on disk.

use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};

use charon_p2p::k1;
use pluto_eth2util::enr::Record;

use crate::error::{CliError, Result};

/// Arguments for the create enr command
#[derive(clap::Args)]
pub struct CreateEnrArgs {
    #[arg(
        long = "data-dir",
        env = "CHARON_DATA_DIR",
        default_value = ".charon",
        help = "The directory where pluto will store all its internal data."
    )]
    pub data_dir: PathBuf,
}

/// Runs the create enr command
///
/// Stores a new charon-enr-private-key to disk and prints the ENR for the
/// provided config. It returns an error if the key already exists.
pub fn run(args: CreateEnrArgs) -> Result<()> {
    if k1::load_priv_key(&args.data_dir).is_ok() {
        let enr_path = k1::key_path(&args.data_dir);
        return Err(CliError::PrivateKeyAlreadyExists { enr_path });
    }

    let key = k1::new_saved_priv_key(&args.data_dir)?;

    let record = Record::new(key, Vec::new())?;
    let key_path = k1::key_path(&args.data_dir);

    let mut writer = io::stdout();
    writeln!(writer, "Created ENR private key: {}", key_path.display())?;
    writeln!(writer, "{}", record)?;
    write_enr_warning(&mut writer, &key_path)?;

    Ok(())
}

/// Writes backup key warning to the terminal
fn write_enr_warning(w: &mut dyn Write, key_path: &Path) -> Result<()> {
    writeln!(w)?;
    writeln!(
        w,
        "***************** WARNING: Backup key **********************"
    )?;
    writeln!(
        w,
        " PLEASE BACKUP YOUR KEY IMMEDIATELY! IF YOU LOSE YOUR KEY,"
    )?;
    writeln!(
        w,
        " YOU WON'T BE ABLE TO PARTICIPATE IN RUNNING A CHARON CLUSTER.\n"
    )?;
    writeln!(w, " YOU CAN FIND YOUR KEY IN {}", key_path.display())?;
    writeln!(
        w,
        "****************************************************************"
    )?;
    writeln!(w)?;
    Ok(())
}
