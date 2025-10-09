//! # Charon CLI
//!
//! Command-line interface for the Charon distributed validator node.
//! This crate provides the CLI tools and commands for managing and operating
//! Charon validator nodes.
//!
//! TODO: This is a placeholder to have an executable crate in the workspace.

use axum::{Router, routing::get};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(|| async { root() }));

    let addr = "0.0.0.0:3000";
    let listener = TcpListener::bind(addr).await.expect("Impossible!");
    println!("Listening on {}", addr);

    axum::serve(listener, app).await.expect("Impossible!");
}

fn root() -> &'static str {
    "Hello, World!"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_says_hello() {
        assert_eq!(root(), "Hello, World!");
    }
}
