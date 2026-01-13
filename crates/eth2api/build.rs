//! # Eth2Api
//!
//! Abstraction to multiple Ethereum 2 beacon nodes. Its external API follows
//! the official [Ethereum beacon APIs specification](https://ethereum.github.io/beacon-APIs/).

use std::io::{Error, ErrorKind, Result};

const BEACON_NODE_OAPI_PATH: &str = "build/beacon-node-oapi.json";

/// Generate the required code from the OpenAPI specification.
pub fn main() -> Result<()> {
    println!("cargo:rerun-if-changed={}", BEACON_NODE_OAPI_PATH);

    let generator = std::process::Command::new("oas3-gen")
        .args([
            "generate",
            "client-mod",
            "-i",
            BEACON_NODE_OAPI_PATH,
            "-o",
            "src",
        ])
        .status()
        .map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                Error::new(
                    ErrorKind::NotFound,
                    "Could not find `oas3-gen`. To install it, run `cargo install oas3-gen`",
                )
            } else {
                error
            }
        })?;
    if !generator.success() {
        return Err(Error::other("`oas3-gen` command failed"));
    }

    std::fs::remove_file("src/mod.rs")?;

    Ok(())
}
