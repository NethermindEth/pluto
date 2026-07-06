# Go simnet harness

A Go test harness that runs simnet-style end-to-end duty tests over
distributed-validator clusters mixing **charon** nodes (in-process, reusing
charon's own `app.Run` and test utilities) and **pluto** nodes (subprocesses
of the pluto binary). It reuses charon `v1.7.1` (the pluto parity reference)
as a library: `cluster.NewForT` fixtures, `testutil/beaconmock`,
`testutil/validatormock` and `testutil/relay`.

## Architecture

```text
                    ┌────────────────────────── Go test process ──────────────────────────┐
                    │                                                                      │
 deterministic      │  relay (in-process libp2p)                                           │
 cluster fixture ─▶ │                                                                      │
 (lock, p2p keys,   │  beaconmock (shared chain state, deterministic duties)               │
  BLS shares)       │      ▲            ▲                             ▲                    │
                    │      │ Go         │ HTTP                        │ HTTP               │
                    │  charon app.Run   gateway[0..k]  ◀── capture ── gateway[k..n]        │
                    │  (in-process,     ▲                             ▲                    │
                    │   real p2p)       │ beacon API                  │ beacon API         │
                    └───────────────────┼─────────────────────────────┼────────────────────┘
                                        │                             │
                                charon app.Run                 pluto run (subprocess)
                              (gateway mode)                          ▲
                                                                      │ validator API
                                                          validatormock (harness-driven)
```

Key design points, mirroring charon's `testutil/integration` simnet:

- **One shared beaconmock, one HTTP gateway per node.** Charon's beaconmock
  implements dynamic behaviour (duties, validators) on its Go client
  interface only; its HTTP server serves static stubs. The gateway fronts
  the shared mock over real HTTP so external processes get a complete
  beacon API, and captures submissions per node for assertions.
- **Real p2p partial-signature exchange.** Upstream simnet uses an
  in-memory ParSigEx transport; the harness omits it so out-of-process
  nodes can participate in QBFT consensus and threshold signing.
- **Assertions at the beacon boundary.** Every node must submit an
  attestation for the same slot, and all payloads must be identical after
  JSON normalization (they are group-signed threshold aggregates). For the
  in-process baseline, upstream-style `BroadcastCallback` assertions are
  used instead.

## Scenarios

| Test | Cluster | Purpose |
|---|---|---|
| `TestSimnetAttesterCharonInProcess` | 3× charon (in-process bmock) | Baseline; validates fixture/relay/assertion plumbing |
| `TestSimnetAttesterCharonViaGateway` | 3× charon via gateway | Proves the gateway serves a complete beacon API over HTTP |
| `TestSimnetAttesterPluto` | 3× pluto | Pure-pluto duty e2e (skips until `pluto run` lands) |
| `TestSimnetAttesterMixed` | 2× charon + 2× pluto, threshold 3 | Cross-implementation interop; threshold forces both implementations to participate in every duty |

## Running

```bash
cd test-infra/harness

# Charon-only scenarios (no pluto binary needed), ~10s total:
go test -v -run 'TestSimnetAttesterCharon' ./...

# Full suite; pluto scenarios skip unless PLUTO_BIN supports `pluto run`:
PLUTO_BIN=../../target/debug/pluto go test -v ./...
```

The pluto scenarios probe `$PLUTO_BIN run --help` and skip cleanly until the
`run` command exists, so they are safe to keep enabled in CI.

### Validating the subprocess path today

The subprocess runner passes `charon run`-shaped flags, so a charon binary
can stand in for pluto to exercise the entire subprocess path (on-disk
fixture layout, flags, readiness polling, HTTP-driven validator mock,
capture assertions):

```bash
PLUTO_BIN=/path/to/charon go test -v -run TestSimnetAttesterMixed ./...
```

## Requirements on `pluto run`

For the pluto scenarios to activate, `pluto run` needs to accept the
charon-equivalent flags the harness passes (see `pluto.go`):
`--lock-file`, `--private-key-file`, `--beacon-node-endpoints`,
`--validator-api-address`, `--monitoring-address`, `--p2p-tcp-address`,
`--p2p-relays` — and to serve the validator API on the configured address
(readiness is detected by TCP connect).

## Versioning

Charon is pinned to the pluto parity reference (`v1.7.1`) in `go.mod`. The
two `replace` directives are copied from charon's own `go.mod` (Go does not
propagate a dependency's replaces) and must be kept in sync when bumping
charon. Bump deliberately alongside the parity target, not to track charon
main.

## Extending

- More duty types: add scenarios passing different beaconmock options
  (upstream simnet's proposer/sync-committee configurations translate
  directly; see `simnetBMockOpts` and charon's `TestSimnetDuties`).
- Fault injection: start N nodes but kill/withhold one below threshold,
  asserting duties still complete (compose-smoke style).
- The gateway logs any non-GET request it reverse-proxies; if a future
  client needs an endpoint dynamically, the log line names it.
