---
name: porting
description: Guides Go→Rust porting for Pluto. Invoke when asked to port, implement parity for, or translate a Go component.
---

## Pre-flight

Before writing any code:

1. **Charon location:** See `charon-guide` for codebase location, version, and structure. Verify once per session if needed.
2. Record the Go reference in the plan: `charon/<path>:<line> (v1.7.1)`
3. **Do not proceed without an approved plan.**

---

## Step 1 — Read Go source

**Architecture context:** See `charon-guide` skill for workflow components, design patterns, and package structure.

For each file in scope:
- What does it do? Inputs, outputs, defaults.
- What are the failure modes and error strings? (copy exact strings)
- What are the user-visible side effects? (stdout, files written, exit codes)
- Trace the main logic flow top-to-bottom.

Do not guess. If behavior is unclear, ask.

---

## Step 2 — Identify missing dependencies

List Go imports and map each to its Rust equivalent:

| Go import | Rust crate/module | Status |
|---|---|---|
| `encoding/json` | `serde_json` | available |
| `crypto/sha256` | `sha2` | available |
| `some/go/pkg` | ??? | **missing — needs decision** |

Flag anything without a clear mapping before continuing.

---

## Step 3 — Inventory surface area

List every function/type to port, in the same order as the Go source:

| Item | Go file:line | Complexity | Notes |
|---|---|---|---|
| `FooCmd` | `cmd/foo.go:12` | Low | CLI entrypoint |
| `parseBar` | `cmd/foo.go:45` | Medium | custom encoding |
| `BazType` | `pkg/baz/baz.go:8` | High | shared with DKG |

Complexity: **Low** = straightforward translation / **Medium** = non-trivial logic or encoding / **High** = protocol-level, crypto, or shared invariants.

---

## Step 4 — Write the plan

For each item in the inventory:

```
### `parse_bar` (charon/cmd/foo.go:45)

Behavior:
  - Accepts hex-encoded 32-byte key, returns decoded [u8; 32]
  - Returns error "invalid key: <hex>" on bad input (match string exactly)

Rust target: `pluto/crates/core/src/foo.rs`

Edge cases:
  - Empty string → error, not panic
  - Odd-length hex → error from hex::decode, wrap in ModuleError

Invariants:
  - Output length always 32 bytes
  - Error string must match Go for CLI parity
```

Do not begin implementing until this plan is approved.

---

## Step 5 — Implement

Follow `rust-style` skill conventions and AGENTS.md golden rules:
- Match Go error strings exactly (critical for functional equivalence)
- Match Go behavior exactly (defaults, edge cases, validation)
- **Implementation approach can differ:** Use idiomatic Rust patterns and data structures when they preserve the same functional behavior. Direct 1:1 translation is not required—functional equivalence is.

Examples where different implementation is acceptable:
- Go's `defer` → Rust RAII (Drop trait)
- Go's `sync.WaitGroup` → Rust `tokio::task::JoinSet`
- Go's `context.Context` → Rust `CancellationToken` + structured concurrency
- Go's mutex-guarded maps → Rust `DashMap` or channels
- Go's manual error wrapping → Rust `#[from]` derive

Keep Go file open alongside. After each function, verify behavior matches before moving on.

---

## Step 6 — Tests

For each ported item:
- Translate Go tests directly; keep the same test name where possible
- For encoding/hashing: generate Go test vectors and hardcode as Rust fixtures
- Use `#[test_case]` for parameterized cases
- Use `#[tokio::test]` for async

Minimum bar: every error path exercised, every Go test translated.

---

## Step 7 — Parity review

Before marking work done, verify functional equivalence with Go implementation:
- CLI flags and arguments match exactly
- Error messages match exactly (critical for user-facing output)
- Wire formats and encodings are identical
- Exit codes match for all error paths
- File outputs (lock files, configs, etc.) are compatible

Use `pluto-review` skill for structured parity review format. Any deviations must be documented with justification.

---

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
