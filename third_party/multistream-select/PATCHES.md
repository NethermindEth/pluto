# multistream-select (vendored fork of 0.13.0)

Vendored from crates.io `multistream-select v0.13.0` and consumed via
`[patch.crates-io]` in the workspace `Cargo.toml`.

## Why

rust-libp2p's multistream-select requires every protocol token to begin with
`/` and rejects anything else at negotiation time (emit, advertise, and
decode). Charon advertises and dials the priority protocol as the slash-less
token `charon/priority/2.0.0` (the only Charon protocol without a leading
slash). To interoperate with unmodified Charon nodes, Pluto must speak that
exact token, which stock multistream-select cannot do.

## Delta vs upstream 0.13.0

All changes are in `src/protocol.rs`, guarded by `// PLUTO PATCH:` comments.
The leading-`/` requirement is relaxed, while the empty-name and message
classification invariants the slash check previously also enforced are
preserved explicitly:

1. `impl TryFrom<&str> for Protocol` — dropped the `!starts_with('/')`
   rejection (outbound propose + listener advertise path); still rejects an
   empty name.
2. `impl TryFrom<Bytes> for Protocol` — dropped the `!starts_with(b"/")`
   rejection (inbound decode path); still rejects an empty name.
3. `Message::decode` single-protocol classification — dropped the
   `msg.first() == Some(&b'/')` condition and replaced its bare-`"\n"`
   exclusion with an explicit `msg.len() > 1` guard. A single protocol line is
   distinguished from an `ls` response by having exactly one (trailing) `\n`
   *and* a non-empty name; the empty `ls` response `Protocols([])` (which
   encodes to `"\n"`) still parses as a zero-entry list, not an empty protocol.

Net effect: acceptance is *widened* only to slash-less non-empty names;
slash-prefixed tokens and the empty-`ls` round-trip behave exactly as upstream,
so all other Pluto p2p protocols are unaffected. No other files differ from
upstream.

## Tests

The upstream quickcheck round-trip property test in `src/protocol.rs` (and its
`Arbitrary` impls) was removed: it depended on rust-libp2p's unpublished
workspace crate `quickcheck-ext`, which is unavailable from crates.io. It is
replaced by deterministic unit tests covering the patched behaviour —
slash-less single-protocol round-trip, empty-name rejection, and the empty
`Protocols([])` round-trip (the case the property test would have caught). The
upstream `tests/` integration tests (slash-prefixed negotiation) are unchanged.

## Maintenance

On a libp2p bump, re-vendor the matching multistream-select version and
re-apply these three edits. The `[patch]` requires the version to stay
semver-compatible with what libp2p depends on (`^0.13.0`), else cargo silently
ignores the patch.

This is enforced in CI: the `test` workflow (`.github/workflows/test.yml`)
fails if any registry-sourced `multistream-select` enters the dependency graph,
so a dropped patch surfaces as a build failure rather than a silent interop
regression.
