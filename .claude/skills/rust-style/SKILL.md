---
name: rust-style
description: General Rust conventions for Pluto. Use it once for understanding the codebase better.
---

## Quality Gate

Run from `pluto/` before declaring any work done:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```

All must pass clean.

---

## Error Handling

Define module-local error enums with `thiserror`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("message: {0}")]
    Variant(String),

    #[error(transparent)]
    Underlying(#[from] OtherError),
}

pub type Result<T> = std::result::Result<T, Error>;
```

Rules:
- Always propagate with `?`; never swallow errors with `.ok()` or `filter_map` in production code
- No `unwrap()`, `expect()`, `panic!()` outside of test code
- No `anyhow` in library crates; use typed errors everywhere

---

## Arithmetic

All arithmetic must be checked — `arithmetic_side_effects = "deny"` is enforced:

```rust
// Bad
let x = a + b;

// Good
let x = a.checked_add(b).ok_or(Error::Overflow)?;
```

---

## Casts

No lossy or unchecked casts — use fallible conversions:

```rust
// Bad
let x = value as u32;

// Good
let x = u32::try_from(value)?;
```

---

## Generalized Parameter Types

Prefer generic parameters over concrete types:

| Instead of | Prefer | Accepts |
|---|---|---|
| `&str` | `impl AsRef<str>` | `&str`, `String`, `&String` |
| `&Path` | `impl AsRef<Path>` | `&str`, `String`, `PathBuf`, `&Path` |
| `&[u8]` | `impl AsRef<[u8]>` | `&[u8]`, `Vec<u8>`, arrays |
| `String` (read-only) | `impl Into<String>` | `&str`, `String` |

Call `.as_ref()` once at the top and bind to a local when used in multiple places. Don't use `impl AsRef<T>` if the function immediately converts to owned — use `impl Into<T>` instead.

---

## Async / Tokio

- Use `async`/`await` for all I/O and network-bound code
- Use `tokio::fs` / `tokio::io` — never blocking `std::fs` in async contexts
- Isolate blocking or CPU-heavy work (crypto, large serialization) with `tokio::task::spawn_blocking`
- Use `tokio::sync::*` primitives when tasks may `.await`
- Use `tokio::time` for timeouts and sleeps — never `std::thread::sleep`
- Use `tokio_util::sync::CancellationToken` instead of cancellation crate

---

## Naming & Formatting

- Modules/functions: `snake_case`
- Types/traits: `PascalCase`
- Constants: `SCREAMING_SNAKE_CASE`
- Named format args always:
```rust
  // Good
  format!("peer {peer_id} connected")
  // Bad
  format!("peer {} connected", peer_id)
```

---

## Documentation

- Every `pub` item must have a doc comment — `missing_docs = "deny"` is enforced
- Adapt doc comments from Go where available; avoid "Type is a …" phrasing
- No `// TODO:` comments in merged code

---

## Testing

- Use `#[tokio::test]` for async tests
- Use `test_case` for parameterized tests:
```rust
#[test_case(1, 2 ; "small")]
#[test_case(10, 20 ; "large")]
fn adds(a: u64, b: u64) { ... }

#[test_case("a" ; "case_a")]
#[tokio::test]
async fn async_case(input: &str) { ... }
```

- For encoding/hashing parity: hardcode Go-derived test vectors as fixtures
- Every error path must be exercised
