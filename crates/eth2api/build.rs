//! # Eth2Api
//!
//! Abstraction to multiple Ethereum 2 beacon nodes. Its external API follows
//! the official [Ethereum beacon APIs specification](https://ethereum.github.io/beacon-APIs/).

use std::io::Result;

const BEACON_NODE_OAPI_PATH: &str = "build/beacon-node-oapi.json";

/// Generate the required code from the OpenAPI specification.
pub fn main() -> Result<()> {
    println!("cargo:rerun-if-changed={}", BEACON_NODE_OAPI_PATH);
    println!("cargo:rerun-if-changed=src/client.rs");
    println!("cargo:rerun-if-changed=src/types.rs");

    std::process::Command::new("oas3-gen")
        .args([
            "generate",
            "client-mod",
            "-i",
            BEACON_NODE_OAPI_PATH,
            "-o",
            "src",
        ])
        .status()?;

    std::fs::remove_file("src/mod.rs")?;

    Ok(())
}
