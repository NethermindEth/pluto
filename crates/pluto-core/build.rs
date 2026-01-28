//! # Charon Core Build Script
//!
//! This build script compiles the protobuf files.

use std::io::Result;

fn main() -> Result<()> {
    pluto_build_proto::compile_protos("src/corepb/v1")?;
    built::write_built_file()?;
    println!("cargo:rerun-if-changed=../../Cargo.lock");

    Ok(())
}
