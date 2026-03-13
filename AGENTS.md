# AGENTS.md — Pluto (Rust) Porting & Review Guide

## Scope

This document applies to work in `pluto/` (the Rust workspace, aka Pluto).
The Go codebase is used only as a behavioral reference.

## Project Structure

Workspace layout (high level):

```text
pluto/
  Cargo.toml               # Workspace members, shared deps, lints
  crates/                  # Workspace crates (Rust source lives here)
    app/                   # Application crate
    build-proto/           # Protobuf/build-time code generation
    cli/                   # `pluto` CLI binary and command wiring
    cluster/               # Cluster types and helpers
    core/                  # Core domain logic
    crypto/                # Cryptographic primitives and helpers
    dkg/                   # Distributed key generation logic
    eth2api/               # Beacon-node API client types/helpers
    eth2util/              # Ethereum consensus utility code
    k1util/                # Secp256k1 utilities
    p2p/                   # P2P networking (libp2p)
    peerinfo/              # Peer info utilities
    relay-server/          # Relay server implementation
    testutil/              # Test helpers/fixtures (workspace-internal)
    tracing/               # Observability/tracing utilities
  test-infra/              # Docker-compose and local infra for integration testing/observability
  deny.toml                # `cargo deny` policy
  rust-toolchain.toml      # Rust toolchain pin
  rustfmt.toml             # Formatting rules
  clippy.toml              # Clippy configuration
```

## Golden Rules

- NEVER IMPLEMENT WITHOUT AN APPROVED PLAN
- ALWAYS READ THE GO SOURCE — NEVER GUESS BEHAVIOR
- ASK QUESTION IF UNDERSPECIFY

- Default to **functional equivalence** with the Go implementation.

## Go Reference (Pinned)

- Upstream reference: `github.com/ObolNetwork/charon` tag `v1.7.1`.
- **Before starting any porting or parity work**, ensure a local Go reference checkout exists.
  - Prefer an existing local `charon/` folder (repo root) if present and pinned to `v1.7.1`.
  - If missing, fetch it first (recommended: submodule/worktree; acceptable: local clone).
  - Treat the Go checkout as **read-only**; never edit Go source files.

Example (local clone):

```bash
git clone --branch v1.7.1 --depth 1 https://github.com/ObolNetwork/charon.git charon
git -C charon rev-parse HEAD
```

## Porting Workflow

When porting a Go command/feature to Rust, follow this sequence:

0. **Ensure Go reference is available**
   - Confirm a local checkout of `charon` at `v1.7.1` exists (see “Go Reference (Pinned)”).
   - Record the Go reference (tag + commit SHA) in the plan/review doc.
1. **Understand Go behavior**
   - Read the Go source files.
   - Explain what it does, inputs/outputs, defaults, and failure modes.
   - Trace the main logic flow and user-visible side effects.
2. **Identify missing dependencies**
   - Compare Go imports vs Rust crates/modules.
3. **Inventory surface area**
   - Keep the same order as the Go implementation for easier review.
   - Rate complexity (Low/Medium/High) and include rough line-count estimates.
4. **Write an implementation plan**
   - For each method: notes, edge cases, invariants (indexing, encoding, ordering, timeouts).
   - Include CLI flags/help text, exit behavior, and error types/strings.

## Core Principles (Enforced by Workspace Lints)

| Principle | Rule |
| --- | --- |
| Functional equivalence | Rust must match Go behavior and outputs by default |
| No panics in prod | No `unwrap()`, `expect()`, `panic!()` in non-test code (`unwrap_used = "deny"`) |
| No unsafe | `unsafe_code = "forbid"` |
| Checked arithmetic | `arithmetic_side_effects = "deny"` — use `checked_*` ops and handle `None` |
| No lossy casts | `cast_*` lints are denied — use fallible conversions and bounds checks |
| Doc all public items | `missing_docs = "deny"` — every `pub` item needs a doc comment |
| Typed errors | Use `thiserror` and `Result<T, E>`; propagate with `?`, do not swallow errors |

## Type Mappings (Go → Rust)

| Go | Rust |
| --- | --- |
| `string` | `String` / `&str` |
| `[]byte` | `Vec<u8>` / `&[u8]` |
| `int64` / `uint64` | `i64` / `u64` |
| `map[K]V` | `HashMap<K, V>` |
| `[]T` | `Vec<T>` |
| `*T` (nullable) | `Option<T>` |
| `error` | `Result<T, E>` |
| `go func()` | `tokio::spawn()` |
| `chan T` | `tokio::sync::mpsc` |

## Async / Tokio

- Prefer `async`/`await` for I/O and network-bound code; use Tokio as the runtime.
- In async contexts, use `tokio::fs` / `tokio::io` instead of blocking `std::fs` / `std::io`.
- If you must call blocking or CPU-heavy code from async (crypto, large serialization, filesystem walks), isolate it with `tokio::task::spawn_blocking`.
- Prefer Tokio sync primitives (`tokio::sync::*`) over `std::sync::*` when tasks may `.await`.
- Use `tokio::time` for timeouts, sleeps, and intervals (avoid `std::thread::sleep`).

## Error Handling

Prefer module-local error enums using `thiserror`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    #[error("message: {0}")]
    Variant(String),

    #[error(transparent)]
    Underlying(#[from] OtherError),
}

pub type Result<T> = std::result::Result<T, ModuleError>;
```

Rules:

- `errors.New("msg")` → enum variant with `#[error("msg")]` (match strings exactly).
- `errors.Wrap(err, "...")` → `#[from]` / `#[source]` where appropriate.
- Always propagate with `?`; avoid silent `filter_map(|x| x.ok())` patterns in production code.

## Code Style

- Naming: modules/functions `snake_case`, types `PascalCase`, constants `SCREAMING_SNAKE_CASE`.
- Formatting: prefer named arguments in formatting macros:
  - ✅ `format!("hello {name}")`
  - ❌ `format!("hello {}", name)`
- Documentation:
  - Prefer copying doc comments from Go and adapting to Rust conventions (avoid “Type is a …”).
  - Avoid leaving TODOs in merged code. If a short-lived internal note is necessary, use `// TODO:` and remove before PR merge.

## Generalized Parameter Types

Prefer generic parameters over concrete types when a function only needs the behavior of a trait. This mirrors the standard library's own conventions and makes functions callable with a wider range of inputs without extra allocations.

| Instead of | Prefer | Accepts |
| --- | --- | --- |
| `&str` | `impl AsRef<str>` | `&str`, `String`, `&String`, … |
| `&Path` | `impl AsRef<Path>` | `&str`, `String`, `PathBuf`, `&Path`, … |
| `&[u8]` | `impl AsRef<[u8]>` | `&[u8]`, `Vec<u8>`, arrays, … |
| `&Vec<T>` | `impl AsRef<[T]>` | `Vec<T>`, slices, arrays, … |
| `String` (owned, read-only) | `impl Into<String>` | `&str`, `String`, … |

Examples:

```rust
// accepts &str, String, PathBuf, &Path, …
fn read_file(path: impl AsRef<std::path::Path>) -> std::io::Result<String> {
    std::fs::read_to_string(path.as_ref())
}

// accepts &str, String, &String, …
fn print_message(msg: impl AsRef<str>) {
    println!(“{}”, msg.as_ref());
}

// accepts &[u8], Vec<u8>, arrays, …
fn hash_bytes(data: impl AsRef<[u8]>) -> [u8; 32] {
    sha256(data.as_ref())
}
```

Rules:

- Call `.as_ref()` once at the top of the function and bind it to a local variable when the value is used in multiple places.
- Do not use `impl AsRef<T>` if the function immediately converts to an owned type anyway — use `impl Into<T>` (or just accept the owned type) in that case.
- Applies to public and private functions alike; the gain is ergonomics, not just API surface.

## Testing

- Translate Go tests to Rust where applicable; keep similar test names for cross-reference.
- Reuse the same fixtures/golden files when possible.
- Use `#[tokio::test]` for async tests.
- Use `test-case` for repeated/parameterized tests (including async):

```rust
#[cfg(test)]
mod tests {
    use test_case::test_case;

    #[test_case(1, 2 ; "small")]
    #[test_case(10, 20 ; "large")]
    fn adds(a: u64, b: u64) {
        let _ = (a, b);
    }

    #[test_case("a" ; "case_a")]
    #[test_case("b" ; "case_b")]
    #[tokio::test]
    async fn async_cases(input: &str) {
        let _ = input;
    }
}
```

- For hashing/serialization parity, generate Go-derived test vectors and hardcode them as Rust fixtures.

## Tooling / Quality Gates

Environment:

- Recommended dev setup: `nix develop` (see `pluto/CONTRIBUTING.md`).
- Rust toolchain is pinned in `pluto/rust-toolchain.toml`.

Commands (run from `pluto/`):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```

## Review Guidelines (Agent + Human)

Principles:

- Functional equivalence first; document and justify deviations.
- Evidence-based: prefer tests, outputs, and file/line references over guesses.
- Minimal change bias; avoid scope creep.
- No time estimates in review output.

When producing a review, include:

1. Summary (1–3 sentences)
2. Findings (ordered by severity)
3. Parity matrix (if applicable)
4. Tests (run or not run)
5. Open questions/assumptions

Severity model:

- Critical: breaks contract, security issue, incompatible output/protocol.
- High: user-visible regression or parity gap with operational impact.
- Medium: behavioral difference with limited impact or edge cases.
- Low: minor inconsistency or optional improvement.

Findings format (use `path:line` references, 1-based):

```text
- [Severity] Title
  Impact: ...
  Evidence: pluto/crates/foo/src/lib.rs:123
  Go reference: charon/cmd/foo.go:456
  Recommendation: ...
```

Parity matrix template:

| Component | Go | Rust | Match | Notes |
| --- | --- | --- | --- | --- |
| CLI flag --foo | present | present | yes | |
| Error string for missing key | "..." | "..." | no | mismatch in punctuation |
| Wire format | pbio | pbio | yes | |
