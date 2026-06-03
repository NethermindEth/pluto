# Pluto — Required Critical E2E Tests (v3, deduplicated)

This plan lists **only the unique e2e tests worth adding**. Every case that is already
covered by an existing test (Rust integration test, unit test, or the `dkg-runner` CI
ceremony) has been removed and recorded in the "Already covered" table with evidence, so
we never write a duplicate.

Charon's runtime is built around the duty workflow: fetch unsigned duty data → QBFT
consensus over an `UnsignedDataSet` → store in `DutyDB` → VC signs → partial-signature
exchange → threshold aggregation → broadcast. Threshold aggregation is only safe if every
node signs the *same* data; consensus alone is not enough — `DutyDB` + slashing protection
are also required.

> **The single biggest fact:** there is **no `pluto run` command** (`crates/cli/src/cli.rs`
> — top-level is `Enr`, `Create`, `Version`, `Relay`, `Dkg`, `Alpha`). The whole duty
> runtime (Group G/S/R below) is blocked on it: many *components* exist (DutyDB,
> ValidatorAPI, ParSigEx, ParSigDB, SigAgg, Tracker, Deadliner, QBFT state machine +
> transport) but **no scheduler, fetcher, broadcaster, or consensus runner wires them into
> a pipeline**, and there is **no slashing-protection DB**.

---

## Already covered — do NOT re-test (removed duplicates)

These were in earlier drafts but are already proven. Evidence is exact (`file:line`).

| Was | Property | Covered by | Evidence |
|-----|----------|------------|----------|
| A1 | Pure Pluto DKG N=4/t=3 completes, lock + shares written | `dkg-runner` CI | job `4 Pluto nodes`, commit `8685291` |
| A2 | Lock consistency across nodes (same lock, same pubkeys, node sigs) | `dkg-runner` semantic verify | `scripts/dkg-runner/ci/verify-output-semantic.sh:85,140,159` |
| A3 | t-of-n signature reconstruction (any 3/4 → valid group sig) | DKG integration test | `crates/dkg/src/frostp2p_integ_test.rs:502-536` |
| A4 | Multi-validator DKG mechanism + count == definition | DKG integration test + verify | `frostp2p_integ_test.rs:33,499`; `verify-output-semantic.sh:119-123` |
| A5 | Deposit-data field correctness (creds/amount/compounding/root/sig) + pubkey match | unit tests w/ golden + verify | `crates/eth2util/src/deposit/mod.rs:45-138,402-579`; `verify-output-semantic.sh:15` |
| B1 | Mixed 2 Charon + 2 Pluto DKG completes, same lock | `dkg-runner` CI | job `2 Charon + 2 Pluto` |
| B3 | Charon-created lock readable by Pluto, sigs validated (V1.0–V1.10) | lock fixtures | `crates/cluster/src/lock.rs:944-994`, `testdata/cluster_lock_v1_*.json` |
| F1 | ParSigEx 3/4 partials aggregate over real libp2p into a valid group sig | committed e2e test | commit `a46ff03`, `crates/parsigex/tests/parsigex_e2e.rs` |
| F2 | Duplicate partials idempotent; threshold matching idempotent | unit tests | `crates/core/src/sigagg.rs:554` (`deduplication_succeeds`); `crates/core/src/parsigdb/memory_internal_test.rs:101` |
| E2/E3 (algorithm level) | QBFT degraded/adversarial: dropped msgs, fuzzing, value-split, no double-decide | state-machine tests | `crates/core/src/qbft/internal_test.rs:1198,1218,2177` |

> Note on QBFT: multi-node consensus on 4 nodes reaching a single decided value is **already
> proven** (`happy()`, `stagger_start`, `dropped_messages`, `fuzzed`, `chain_split`) — but only
> over **in-memory channels with a fake clock**, never over libp2p. That gap is E1 below.

---

# Phase 1 — Unique tests writable now (no `pluto run` needed)

Seven tests. None duplicate existing coverage. Ordered by leverage.

| ID | Test | What it uniquely proves | Func | Why not a duplicate |
|----|------|-------------------------|:----:|---------------------|
| **E1** | Full QBFT round on 4 Pluto nodes over **real libp2p** (via a small consensus runner) | Wire serialization + the #448 transport + a runner actually reach one decided value across the network | 🟡 needs a consensus runner | In-memory consensus is tested; `transport.rs`/`sniffer.rs` are `#![allow(dead_code)]` and `qbft::run()` is never driven over libp2p. Highest-leverage runtime work before `pluto run`. E2 (crashed node) / E3 (Byzantine proposal) become cheap variants once the runner exists. |
| **F3** | Invalid partial signature from one peer is rejected; no aggregate from mixed signing roots | Byzantine protection at the signing layer with **real cryptographic verification** | 🟡 ParSigEx verify is a no-op stub today | `verify_fn_error` (`sigagg.rs:698`) only tests a callback that returns an error, not a cryptographically invalid signature. Requires wiring real verification. |
| **B4** | Reconstruct a valid group signature from a **mix of Pluto + Charon shares** | Share/crypto compatibility, not just JSON parsing | 🟢 | A3 is pure-Pluto reconstruction; B3 is parse-only; `dkg-runner` checks the `signature_aggregate` byte length, never a fresh t-of-n reconstruction from mixed shares. |
| **C1** | N nodes connect over TCP by ENR and exchange + validate peerinfo (version / lock_hash / git) | peerinfo really travels a live connection and is checked | 🟢 | Only protobuf round-trip unit tests (`peerinfo/protocol.rs:518`) and an example binary exist — no automated multi-node exchange. |
| **C4** | Wrong protocol-version / lock-hash peer is rejected/marked incompatible over the wire, no crash | Fail-closed compatibility behavior end-to-end | 🟢 | Mismatch logic exists (`peerinfo/protocol.rs:64-193`) but no test asserts the rejection behavior on a live connection. |
| **D2** | Two isolated nodes (no direct route) exchange p2p traffic **through the Pluto relay** | The relay actually carries circuit traffic | 🟡 | Only `RelayManager` state-machine unit tests (`p2p/relay.rs:913`) + example/docker-compose; no automated traffic-through-relay test. |
| **D1** | `pluto relay` accepts **multiple real libp2p client circuit reservations** | Clients can reserve/connect, not just HTTP responds | 🟢 | HTTP `/enr` and ENR fields are tested (`relay-server/tests/http_integration.rs:128`); the circuit-reservation path is not. |

### Optional small add-ons (not standalone tests)

- **A5+** — extend `verify-output-semantic.sh` to also check `withdrawal_credentials` /
  `amount` / `fee_recipient` against the definition (currently only the pubkey is matched).
- **B2** — run real `charon` against a pure-Pluto `cluster-lock.json` (cheap; B1 already
  proves most of the format/wire compat).

---

# Phase 2 — Unique but BLOCKED on `pluto run`

These are the essence of a distributed validator and nothing in the codebase covers them,
but they **cannot be written or even reproduced** until the runtime exists (scheduler +
fetcher + consensus runner + broadcaster + ValidatorAPI submit handlers), and the
anti-slashing cases additionally need a **persistent slashing-protection DB** (🔴 absent).

## G. Validator duty execution

| ID | Test | Why it matters | Blocker |
|----|------|----------------|---------|
| **G1** | Attestation duty full pipeline (scheduler→consensus→VC sign→parsig→agg→submit) | The single most important runtime proof | `pluto run` |
| **G2** | Block proposal — exactly one valid block per validator+slot | Most critical proposer path | `pluto run` |
| **G4** | Multi-slot simnet, 3–4 nodes, mock beacon + mock VC | Direct parity with Charon `TestSimnetDuties` (mocks already exist) | `pluto run` |

## S. Runtime safety / anti-slashing

| ID | Test | Why it matters | Blocker |
|----|------|----------------|---------|
| **S1** | Malicious BN gives conflicting attestation data to different nodes → cluster signs one root or nothing | Prevent double vote | `pluto run` |
| **S2** | Malicious BN attempts double proposal → ≤1 block signature per validator+slot | Prevent double proposal | `pluto run` |
| **S4** | Compromised VC submits a duty not matching consensus → partial rejected, never exchanged/aggregated | VC not trusted blindly | `pluto run` |
| **S7** | Network partition 2/2 → no side signs/broadcasts | Safety over liveness | `pluto run` |
| **S8** | Network partition 3/1 → majority continues, minority cannot sign | Majority liveness, minority safety | `pluto run` |
| **S12** | `privkeylock`: second runtime on same keys cannot start/sign | Prevent duplicate signer (privkeylock primitive exists) | `pluto run` |
| **S3** | Surround/double vote blocked across restart | Persistent slashing history | `pluto run` **+ slashing-protection DB (🔴 missing)** |

## R. Runtime Charon compatibility

| ID | Test | Why it matters | Blocker |
|----|------|----------------|---------|
| **R1** | Mixed runtime 3 Charon + 1 Pluto → duties pass, all agree on duty hash | Minimum real interoperability | `pluto run` |
| **R2** | Mixed runtime 2 Charon + 2 Pluto → attestation + proposer duties pass | Stronger parity | `pluto run` |

---

## Reference: Charon's own e2e / integration tests (parity targets)

| Charon test | What it does | Pluto mapping |
|---|---|---|
| `testutil/integration/simnet_test.go` · TestSimnetDuties | Full duty cycle, mock beacon + mock VC, 3 nodes | G1, G2, G4 (blocked) |
| `testutil/integration/ping_test.go` · TestPingCluster | DiscV5 → relay → direct upgrade; ping all-to-all | C1, D1, D2 |
| `core/consensus/qbft/qbft_test.go` · TestQBFTConsensus | Multi-node QBFT over real libp2p | E1 (in-memory already covered) |
| `core/parsigex/parsigex_test.go` · TestParSigEx | Partial-sig broadcast + receive across peers | F1 (done), F3 |
| `dkg/dkg_test.go` · TestDKG | Full DKG: FROST + Pedersen, lock publish | A1–A5 (covered) |
| `dkg/dkg_test.go` · TestSyncFlow | DKG resilient to peer dropout / reconnect | (deferred — not in critical set) |

### Parity verdict

- **Covered:** DKG ceremony + artifacts (A1–A5, via `frostp2p_integ_test` + `dkg-runner`),
  Charon lock parsing (B3), mixed DKG (B1), ParSigEx aggregation (F1), QBFT state machine
  incl. degraded/adversarial (E2/E3 algorithm level).
- **Unique gaps writable now:** E1, F3, B4, C1, C4, D1, D2.
- **Unique gaps blocked on `pluto run`:** the whole duty cycle (G), anti-slashing/partition
  safety (S), and mixed runtime (R). S3 additionally needs a slashing-protection DB.
- **Bottom line for stakeholders:** everything provable *without* a live runtime is covered
  or has a short, unique backlog (7 tests). The product-defining proofs — that a validator
  safely executes duties and is never slashed — cannot exist until `pluto run` and slashing
  protection are built. A green CI today means "the building blocks are sound", not "the
  runtime is ready".
