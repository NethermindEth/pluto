# Charon-parity fixture-replay harness

Each JSON file in this directory drives one scenario through Pluto's
`validatorapi::Handler` trait and asserts the outcome matches the
behaviour established by Charon's Go reference.

The harness lives in `crates/core/tests/charon_parity.rs` plus its
sibling submodules; run it with:

```bash
cargo test -p pluto-core --test charon_parity --all-features -- --nocapture
```

`--nocapture` lets the per-run `ParitySummary` reach stdout — useful as
a porting progress dashboard.

## Fixture format

```jsonc
{
  "name": "scenario_id",                       // stable identifier
  "endpoint": "submit_proposal",               // Handler method name
  "status":   "implemented",                   // "implemented" | "unimplemented" | "partial"
  "go_source": "core/validatorapi/validatorapi.go:551-605",   // optional citation
  "go_test":   "core/validatorapi/validatorapi_test.go:TestSubmitProposal",
  "setup": {                                   // optional
    "beacon_mock": {
      "use_validator_set_a": true,
      "deterministic_proposer_duties": 1,
      "deterministic_attester_duties": null
    },
    "share_idx": 1,
    "builder_enabled": false
  },
  "request": {
    "kind": "submit_proposal",                 // tag matches `endpoint`
    "proposal": { /* typed payload, or {} for pending */ }
  },
  "expected": {                                // omit when status="unimplemented"
    "kind": "ok",                              // "ok" | "err"
    "body": { /* JSON-deep-equality target */ }
  },
  "notes": "Optional. Short, surfaced on failure."
}
```

### Status semantics

| Status            | Run behaviour                                                                                              |
|-------------------|------------------------------------------------------------------------------------------------------------|
| `implemented`     | Handler must return exactly `expected`. Any panic, any mismatch ⇒ **fail**.                                |
| `unimplemented`   | Handler must panic with `unimplemented!()`. Returning Ok/Err is a **graduation candidate** — fail loudly. |
| `partial`         | Handler call is run, but outcome is **logged, not compared**. Use sparingly for known, tracked TODOs.     |

### Pending fixtures

`status: "unimplemented"` fixtures may set their `request.{opts, proposal, …}`
payload to `{}` or `[]`. The harness substitutes a hardcoded stub
value (see `stub_*` helpers in `tests/charon_parity/harness.rs`) for
complex payload types like `VersionedSignedProposal` — the handler
panics with `unimplemented!()` before reading the value, so the
substituted stub never reaches user code.

Once an endpoint is ported, the corresponding stub starts returning
`Ok(...)` instead of panicking. The harness then flags the fixture as
a "graduation candidate" and fails the run, forcing the porter to:

1. Move the fixture from `pending.json` into one or more scenario
   files under the same endpoint directory.
2. Set `status: "implemented"` and fill in `expected.body` with the
   real response shape (or `expected.kind: "err"` for failure paths).
3. Cite the Charon test source in `go_test`.

### Setup primitives (V1)

- `beacon_mock.use_validator_set_a` — registers Charon's built-in
  `validator_set_a` (3 active validators with known pubkeys).
- `beacon_mock.deterministic_proposer_duties: <factor>` — seeds the
  mock with Charon's `WithDeterministicProposerDuties(factor)`.
- `beacon_mock.deterministic_attester_duties: <factor>` — same for
  attester duties.
- `share_idx` — threshold BLS share index (default `1`).
- `builder_enabled` — toggles the Component's builder mode flag.

DutyDB pre-population and hook registration are out of scope for V1 —
add them when the first dutydb/hook-dependent endpoint graduates from
`unimplemented` to `implemented`.

## Adding fixtures for a newly-ported endpoint

1. `cargo test -p pluto-core --test charon_parity` — confirm the
   harness currently passes (the `pending.json` for your endpoint
   should be in the "pending" tally).
2. Port the endpoint as usual. Re-run; the harness will now fail with
   a graduation message.
3. Replace the endpoint's `pending.json` with one or more scenario
   files (`happy_path.json`, `upstream_400.json`, …). Pin
   `expected.body` from Charon's test fixtures
   (`charon/core/validatorapi/testdata/...`) where available, or by
   capturing Pluto's own response and cross-checking against Go.
4. Cite the Charon test name in each fixture's `go_test` field.

## Out of scope (deferred)

- Dual-server differential testing (running real Charon + Pluto behind
  HTTP and diffing responses). A heavier follow-up.
- Auto-extraction of fixtures from Charon's Go table tests. Manual for
  now; the citation fields make later migration mechanical.
- Header-level checks (`Eth-Consensus-Version`, content-type
  negotiation). Lives in the router, not the Handler — track
  separately if needed.
