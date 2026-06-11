//! # Charon Core Build Script
//!
//! This build script compiles the protobuf files.

use std::io::Result;

fn main() -> Result<()> {
    built::write_built_file()?;
    println!("cargo:rerun-if-changed=../../Cargo.lock");

    Ok(())
}
