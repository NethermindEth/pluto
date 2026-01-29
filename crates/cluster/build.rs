//! # Charon Cluster Build Script
//!
//! This build script compiles the protobuf file for the cluster manifest.

use std::{io::Result, path::PathBuf};

fn main() -> Result<()> {
    let proto_file = "src/manifestpb/manifest.proto";
    let out_dir = PathBuf::from("src/manifestpb");

    // Compile the protobuf file and output to src/manifestpb
    let mut config = prost_build::Config::new();
    config
        .btree_map(["."])
        .bytes(["."])
        .out_dir(&out_dir)
        .compile_protos(&[proto_file], &["src/"])?;

    println!("cargo:rerun-if-changed={}", proto_file);
    println!("cargo:rerun-if-changed=build.rs");

    Ok(())
}
