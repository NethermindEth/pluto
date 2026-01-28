//! # Charon DKG Build Script
//!
//! This build script compiles the protobuf files.

use std::io::Result;

fn main() -> Result<()> {
    pluto_build_proto::compile_protos("src/dkgpb/v1")
}
