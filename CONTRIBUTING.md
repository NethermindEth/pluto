# Contributor's guide

## Prerequisites

### Using Nix (Recommended)

The easiest way to set up the development environment is using [Nix](https://nixos.org/download/):

```sh
nix develop
```

This provides everything needed to build and check the project — the pinned Rust toolchain (from `rust-toolchain.toml`) and nightly `rustfmt`, plus the auxiliary dependencies (Protobuf, Go, oas3-gen, cargo-deny, cargo-machete, cargo-llvm-cov) — and configures git hooks.

### Manual Setup

If you prefer not to use Nix, install the following manually:

* [Rust](https://www.rust-lang.org/tools/install)
* [Protobuf](https://protobuf.dev/installation/)
* [Docker](https://www.docker.com/)
* [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) - `cargo install cargo-deny@0.19.0`
* [cargo-machete](https://github.com/bnjbvr/cargo-machete) - `cargo install cargo-machete@0.9.2`
* [oas3-gen](https://github.com/eklipse2k8/oas3-gen) - `cargo install oas3-gen@0.24.0`

Then install the pre-push git hook:

```sh
git config core.hooksPath .githooks
```

The pre-push hook (`.githooks/pre-push`) runs the full quality-gate sequence in order: `cargo deny check`, `cargo machete`, `cargo +nightly fmt --all -- --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings`, and `cargo test --locked --workspace --all-features`. All checks must pass before a push is accepted.

## Building
To build the project with all its crates, run:

```sh
cargo build --workspace --all-features
```

## Run Unit and Integration Tests
To run all tests - unit and integration - run:

```sh
cargo test --workspace --all-features
```

> **Note:** `--all-features` enables the `integration` feature in `crates/eth2api`, which uses [testcontainers](https://github.com/testcontainers/testcontainers-rs) and therefore requires a **running Docker daemon**. Without Docker the integration tests will fail with opaque errors. Smoke tests that invoke Go tooling (e.g. `create-cluster-compare.sh`) additionally require [Go](https://go.dev/dl/) to be installed.

## Running the Rust Documentation Locally
To build the documentation locally:

```sh
cargo doc --workspace --all-features --no-deps
```

## Performance
When contributing, besides correctness, it is also important to ensure good performance and reproducibility of the results.
We recommend using [Criterion](https://crates.io/crates/criterion) for general benchmarking, as it provides a well-structured framework that allows reproducible benchmarks by just running a few commands.
We want to highlight 2 very useful commands in Criterion:
- `cargo bench -- --save-baseline <name>` allows you to save a benchmark under a given name to serve as baseline.
- `cargo bench -- --baseline <name>` compares the current benchmark against a previously saved baseline.

As an alternative to Criterion, we also recommend [Divan](https://crates.io/crates/divan), which provides a simpler API and a more intuitive benchmark organization.
Criterion is still recommended for more rigorous statistical analysis, but Divan is great for most applications.

For performance, the profiling cycle is a 3-step process in which you need to first measure the resources consumed by your application, then isolate the most consuming ones, and finally optimize them.
This cycle repeats until the performance goals are met.
To carry out this optimization cycle, we recommend the following profiling tools, as they are powerful, general-purpose, and are either written or well integrated with Rust:
* [Hyperfine](https://crates.io/crates/hyperfine): Provides a simple CLI interface that allows us to benchmark compiled binaries.
* [Samply](https://crates.io/crates/samply): Generates a detailed graphic of the different operations and their time in the application. We recommend it over [FlameGraph](https://crates.io/crates/flamegraph) as it allows for filtering, and the webserver viewer provides a better experience than the `.svg` your get from Flamegraph.
* [Dhat](https://crates.io/crates/dhat): Measures memory allocations within the application.

### Hyperfine

Once [installed](https://github.com/sharkdp/hyperfine?tab=readme-ov-file#installation), we can simply run:
```sh
hyperfine <binary>
```
### Samply

Samply creates [flame graphs](https://www.youtube.com/watch?v=D53T1Ejig1Q&t=813s) and detailed call stacks with a browser-based [Firefox Profiler](https://profiler.firefox.com/).

Run
```sh
cargo install --locked samply
```

You [may need](https://github.com/mstange/samply/?tab=readme-ov-file#description) to grant some system access to `samply`.

Into your `Cargo.toml` to add debug symbols in profiling mode:

```toml
[profile.profiling]
inherits = "release"
debug = true
```

Otherwise, reading the output will be impossible.

Then, we can run:
```sh
samply record <binary>
```
This command will open a browser page that contains a graphic representation of where the time is being spent in our application.

### Dhat
We can add Dhat as a dependency:
```toml
[dependencies]
dhat = "0.3"

[features]
dhat-heap = []
```
Then we need to replace the default allocator with the `dhat` allocator.
And set the profiler when the `dhat-heap` feature is enabled:
```rust
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();
}
```
If we run the binary again with the `dhat-heap` feature enabled, we will get a JSON file with the memory allocations done during the execution.

Many other profiling libraries exist, please check the [Rust Performance Book](https://nnethercote.github.io/perf-book/profiling.html) for a more detailed list.
But these 3 should be enough for the average application to identify bottlenecks and optimize them.

For async-rust we also recommend: [Tracing](https://crates.io/crates/tracing), [Tokio-Console](https://crates.io/crates/tokio-console), and [Oha](https://crates.io/crates/oha).
For Rayon-based parallel Rust code, we recommend Samply.
It provides good profiling despite missing some multithreading details.
