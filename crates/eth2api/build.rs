//! # `Eth2Api`
//!
//! Abstraction to multiple Ethereum 2 beacon nodes. Its external API follows
//! the official [Ethereum beacon APIs specification](https://ethereum.github.io/beacon-APIs/).

use regex::Regex;
use std::{
    io::{Error, ErrorKind, Result},
    sync::LazyLock,
};

const BEACON_NODE_OAPI_PATH: &str = "build/beacon-node-oapi.json";

/// Generate the required code from the `OpenAPI` specification.
pub fn main() -> Result<()> {
    println!("cargo:rerun-if-changed={BEACON_NODE_OAPI_PATH}");

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

    // Ensure all structs have both Serialize and Deserialize derives
    ensure_serde_derives("src/types.rs")?;

    Ok(())
}

static DERIVE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"#\[derive\(([^)]*)\)\]").expect("Valid comptime regex"));

static DESERIALIZE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(Deserialize)").expect("Valid comptime regex"));

/// Ensures all `#[derive(...)]` attributes that contain `Deserialize` also
/// contain `Serialize`.
///
/// This is useful for mocking responses in tests.
fn ensure_serde_derives(path: &str) -> Result<()> {
    let content = std::fs::read_to_string(path)?;

    // Regex to match #[derive(...)] attributes, handling multi-line cases
    // Captures the entire derive attribute including its contents
    let derive_re = &DERIVE_RE;

    let updated = derive_re.replace_all(&content, |caps: &regex::Captures| {
        let full_match = &caps[0];
        let inner = &caps[1];

        // Check if `Deserialize` is present but `Serialize` is not
        let has_deserialize = inner.contains("Deserialize");
        let has_serialize = inner.contains("Serialize");

        if has_deserialize && !has_serialize {
            // Find the position of Deserialize and add Serialize before it
            let new_inner = DESERIALIZE_RE.replace(inner, "Serialize, Deserialize");
            format!("#[derive({new_inner})]")
        } else {
            // Don't change the derive attribute
            full_match.to_string()
        }
    });

    std::fs::write(path, updated.as_ref())?;

    Ok(())
}
