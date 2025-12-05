//! # Charon Peerinfo Build Script
//!
//! This build script compiles the protobuf files.

use std::io::Result;

fn main() -> Result<()> {
    charon_build_proto::compile_protos("src/peerinfo/peerinfopb/v1")?;
    charon_build_proto::compile_protos("src/log/loki/lokipb/v1")?;

    Ok(())
}
