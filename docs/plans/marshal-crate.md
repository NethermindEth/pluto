# Plan — `Marshal` trait + `register_signed_data_codecs!` table

Status: drafted, awaiting approval before implementation.

## Goal

Make round-trip wiring of `SignedData` types *impossible to forget*. Today,
`crates/core/src/parsigex_codec.rs` hand-codes serialize/deserialize for each
type in two long blocks. Adding a new type requires editing both halves,
choosing a codec consistent across both, and remembering to write a round-trip
test. Any of those steps can be skipped silently.

This plan introduces:

- A small `Marshal` trait so that serialization is a method call on
  `SignedData` types.
- A single `register_signed_data_codecs!` table in `signeddata.rs` that is the
  *only* legal way to make a type usable as `SignedData`.
- Auto-generated round-trip tests so that the codec-symmetry contract is
  checked by CI for every entry.

No new crate. No proc-macro. No `inventory`. Pure `macro_rules!` inside
`pluto-core`.

## Why this shape

Solidity comes from generated *tests*, not generated *dispatch*. The
single-table `macro_rules!` approach makes the following failures impossible
to ship:

| Failure mode                                 | Caught by                                                    |
| -------------------------------------------- | ------------------------------------------------------------ |
| New `SignedData` type, never wired           | Compile error — the type has no `Marshal` impl               |
| Serialize and deserialize disagree on codec  | Generated round-trip test per entry                          |
| New `DutyType` variant, dispatch not updated | Exhaustive `match DutyType` (already today)                  |
| JSON-encoded payload no longer decodes       | Generated JSON-fallback test per `ssz_then_json` entry       |
| Registered to the wrong duty / priority      | Generated duty-dispatch test per entry                       |
| Wire format drifts from Go Charon            | Existing Go fixture tests in `ssz_codec.rs`                  |

### Rejected alternative — proc-macro + `inventory`

An earlier draft proposed a `pluto-marshal` / `marshal-derive` crate pair with
separate `#[marshal(...)]` and `#[duty(...)]` attributes, registered via
`inventory::submit!`. Rejected because:

- **Asymmetric codecs go undetected.** Without auto-generated round-trip
  tests, a type can advertise one codec on the encode side and a different
  one on the decode side; nothing fails to compile.
- **`inventory` registration is link-time, not compile-time.** A missed
  submission silently degrades to "unsupported duty" at runtime instead of
  being a build error.
- **Two new crates, a new dep, and worse error messages on macro misfire**, in
  exchange for no additional safety vs. a `macro_rules!` table — the test
  generation, not the dispatch shape, is what closes the holes.

## File layout (no new crates)

```text
crates/core/src/
  marshal.rs           # NEW: Marshal trait, MarshalError, helpers, the
                       #      register_signed_data_codecs! macro
  signeddata.rs        # invokes register_signed_data_codecs! once
  parsigex_codec.rs    # collapses to two thin functions
  ssz_codec.rs         # unchanged
```

## Trait (`crates/core/src/marshal.rs`)

```rust
pub trait Marshal {
    fn marshal(&self) -> Result<Vec<u8>, MarshalError>;

    fn unmarshal(bytes: &[u8]) -> Result<Self, MarshalError>
    where
        Self: Sized;
}

#[derive(Debug, thiserror::Error)]
pub enum MarshalError {
    #[error("ssz: {0}")]    Ssz(String),
    #[error("json: {0}")]   Json(#[from] serde_json::Error),
    #[error("custom: {0}")] Custom(String),
    #[error("all codecs failed")] AllFailed,
}

#[doc(hidden)]
pub fn looks_like_json(bytes: &[u8]) -> bool { /* `{`-prefix sniff */ }
```

Dyn-compatibility:

- `marshal(&self)` — vtable-dispatchable, works on `dyn Marshal` /
  `Box<dyn Marshal>`.
- `unmarshal -> Self` — guarded by `where Self: Sized`, statically dispatched
  only. The duty-keyed `Box<dyn SignedData>` decode path lives in
  `parsigex_codec.rs` and uses the same generated table (see below); no
  separate registry crate needed.

`SignedData` becomes `pub trait SignedData: Marshal + ... { ... }`, so any
existing `Box<dyn SignedData>` value can call `.marshal()` directly.

## The macro

`register_signed_data_codecs! { ... }` is invoked exactly once, in
`signeddata.rs`, with a row per `SignedData` type:

```rust
register_signed_data_codecs! {
    Attestation {
        duty: Attester,
        priority: 0,
        codec: ssz_then_json(
            ssz_codec::encode_phase0_attestation,
            ssz_codec::decode_phase0_attestation,
        ),
        sample: sample_phase0_attestation,
    },
    VersionedAttestation {
        duty: Attester,
        priority: 1,
        codec: ssz_then_json(
            ssz_codec::encode_versioned_attestation,
            ssz_codec::decode_versioned_attestation,
        ),
        sample: sample_versioned_attestation,
    },
    SignedAggregateAndProof {
        duty: Aggregator, priority: 0,
        codec: ssz_then_json(...), sample: ...,
    },
    VersionedSignedAggregateAndProof {
        duty: Aggregator, priority: 1,
        codec: ssz_then_json(...), sample: ...,
    },
    SignedSyncMessage {
        duty: SyncMessage, priority: 0,
        codec: ssz_then_json(...), sample: ...,
    },
    SignedSyncContributionAndProof {
        duty: SyncContribution, priority: 0,
        codec: ssz_then_json(...), sample: ...,
    },
    VersionedSignedProposal {
        duty: Proposer, priority: 0,
        codec: ssz_then_json(...), sample: ...,
    },

    VersionedSignedValidatorRegistration {
        duty: BuilderRegistration,
        codec: json,
        sample: ...,
    },
    SignedVoluntaryExit         { duty: Exit,                   codec: json, sample: ... },
    SignedRandao                { duty: Randao,                 codec: json, sample: ... },
    Signature                   { duty: Signature,              codec: json, sample: ... },
    BeaconCommitteeSelection    { duty: PrepareAggregator,      codec: json, sample: ... },
    SyncCommitteeSelection      { duty: PrepareSyncContribution,codec: json, sample: ... },
}
```

### Codec forms

```text
codec: json
codec: ssz                                          // uses ssz::{Encode,Decode} on Self
codec: ssz_then_json(enc_fn, dec_fn)                // custom SSZ + JSON fallback on decode
codec: json_then_ssz(enc_fn, dec_fn)                // JSON-first variant if ever needed
```

Custom codec function signatures, exactly:

```rust
fn enc_fn(value: &Self) -> Result<Vec<u8>, impl Into<MarshalError>>;
fn dec_fn(bytes: &[u8]) -> Result<Self, impl Into<MarshalError>>;
```

Wrapper newtypes (e.g. `Attestation(phase0::Attestation)`) whose existing
helpers take the inner field get a one-line adapter at the top of
`signeddata.rs`. No field-accessor magic in the macro.

### What the macro emits per entry

For `Foo { duty: D, priority: P, codec: ssz_then_json(enc, dec), sample: s }`:

1. **`impl Marshal for Foo`** — `marshal` calls `enc(self)`, `unmarshal` does
   the JSON-sniff then `dec(bytes)` then JSON fallback. Single source of
   truth for the codec choice.
2. **A registry entry** — a `const fn` slot consumed by
   `parsigex_codec::deserialize_signed_data` to dispatch by `(duty, priority)`.
   Implemented as a generated `pub(crate) fn dispatch_table()` returning a
   `&'static [(DutyType, u8, fn(&[u8]) -> Result<Box<dyn SignedData>, _>)]`.
3. **`#[test] fn roundtrip_foo()`** in a `#[cfg(test)] mod generated_tests`
   block: `let v = s(); let bytes = v.marshal().unwrap(); let back =
   Foo::unmarshal(&bytes).unwrap(); assert_eq!(v, back);`
4. **`#[test] fn json_fallback_foo()`** when the codec is `ssz_then_json` /
   `json_then_ssz`: encode via `serde_json::to_vec`, decode via `unmarshal`,
   assert equal. This catches "type silently dropped JSON support".
5. **`#[test] fn duty_dispatch_foo()`**: builds the sample, marshals it, then
   calls `parsigex_codec::deserialize_signed_data(duty, &bytes)` and downcasts
   to `Foo`, asserting equal. This catches "registered to the wrong duty" and
   "priority order is wrong".

### What `parsigex_codec.rs` looks like after

```rust
pub fn serialize_signed_data(
    data: &dyn SignedData,
) -> Result<Vec<u8>, ParSigExCodecError> {
    data.marshal().map_err(Into::into)
}

pub fn deserialize_signed_data(
    duty: &DutyType,
    bytes: &[u8],
) -> Result<Box<dyn SignedData>, ParSigExCodecError> {
    let is_json = pluto_marshal::looks_like_json(bytes);
    for (entry_duty, _priority, decoder) in marshal::dispatch_table() {
        if entry_duty != duty { continue; }
        match decoder(bytes) {
            Ok(v) => return Ok(v),
            Err(_) if !is_json => continue, // try next priority
            Err(e) => return Err(e.into()),
        }
    }
    Err(ParSigExCodecError::UnsupportedDutyType)
}
```

The duty-handling for `BuilderProposer` (deprecated) and
`Unknown`/`InfoSync`/`DutySentinel(_)` stays as explicit early-returns before
the table walk. The match on `DutyType` remains exhaustive.

## Migration steps

1. Add `crates/core/src/marshal.rs` with the trait, error, helper, and macro.
   Macro stub first; flesh out per-entry expansion incrementally.
2. Make `SignedData: Marshal`.
3. Add adapter helpers in `signeddata.rs` for wrappers whose `ssz_codec`
   helpers take the inner field (`encode_phase0_attestation` etc.). One-line
   each.
4. Add `sample_*` fns near the existing test fixtures in `signeddata.rs` (or
   a new `signeddata::samples` module) so they're reachable both by the
   generated tests and by callers who already write hand tests.
5. Invoke `register_signed_data_codecs! { ... }` once, listing every
   `SignedData` type.
6. Replace `parsigex_codec::serialize_signed_data` / `deserialize_signed_data`
   with the thin wrappers shown above. Keep the existing public signatures so
   no caller changes.
7. Delete the now-redundant hand round-trip tests in
   `crates/core/src/parsigex_codec.rs` that the generated tests subsume —
   keep the Go-fixture tests in `ssz_codec.rs` untouched.
8. Run the full workspace gates from `AGENTS.md`.

## Quality gates

- `cargo +nightly fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features` — generated round-trip,
  json-fallback, and duty-dispatch tests must all pass.
- Existing Go-fixture tests in `ssz_codec.rs` must pass byte-for-byte.
- `cargo deny check`

## Open decisions

1. **Trait module path.** `pluto_core::marshal::{Marshal, MarshalError}` vs.
   re-export at `pluto_core::Marshal`. I lean on a `marshal` submodule with a
   re-export at the crate root for the trait and error types only.
2. **Sample functions** live where? Options:
   - Inline in `signeddata.rs` next to the `register_*!` invocation
     (everything in one file, ~50 small fns).
   - In `crates/core/src/signeddata/samples.rs` to keep `signeddata.rs`
     readable.
   I lean toward option 2 since the file is already large.
3. **Sealed-trait extra check.** Should we go further and seal `SignedData` so
   that adding a new struct that *implements* `SignedData` outside the macro
   table is impossible? It's an extra layer of "no one can forget"; downside
   is mild boilerplate. Worth doing if the team is OK with it.
4. **Sample-fn signature.** `fn() -> Self` (simple) vs.
   `fn(seed: u64) -> Self` (lets the generated test do
   property-style multi-sample round-trips). I'd start with `fn() -> Self` and
   add a second seeded sample only if it pulls its weight.

## Out of scope

- Replacing the SSZ codec helpers in `ssz_codec.rs`. Charon-versioned-header
  logic stays as bespoke functions; the macro just delegates to them.
- Changing the wire format. Behavior is byte-for-byte identical to today.
- Touching the proto-level `parsigex` codec — this plan only refactors the
  in-memory `SignedData` ↔ bytes step.
- Reusing `Marshal` outside `SignedData`. The trait lives in `pluto-core`;
  if a second user appears later, the trait can be lifted into a
  `pluto-marshal` crate at that point with no behavior change.
