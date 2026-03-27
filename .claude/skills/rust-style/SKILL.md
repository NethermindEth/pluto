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
- `errors.New("msg")` → enum variant with `#[error("msg")]` (match strings exactly)
- `errors.Wrap(err, "...")` → `#[from]` / `#[source]` where appropriate
- Every field/payload in an error variant **must** appear in its `#[error("...")]` format string. If a field is not surfaced in the error message, either include it or remove it from the variant. Dead payload (captured but never displayed) is not allowed.
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

## Async / Tokio

- Prefer `async`/`await` for I/O and network-bound code; use Tokio as the runtime.
- In async contexts, use `tokio::fs` / `tokio::io` instead of blocking `std::fs` / `std::io`.
- If you must call blocking or CPU-heavy code from async (crypto, large serialization, filesystem walks), isolate it with `tokio::task::spawn_blocking`.
- Prefer Tokio sync primitives (`tokio::sync::*`) over `std::sync::*` when tasks may `.await`.
- Use `tokio::time` for timeouts, sleeps, and intervals (avoid `std::thread::sleep`).

---

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
