//! # Charon Core Build Script
//!
//! This build script compiles the protobuf files.

use std::io::Result;

fn main() -> Result<()> {
    charon_build_proto::compile_protos("src/corepb/v1")
}
