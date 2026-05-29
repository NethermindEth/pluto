# Port `core/scheduler` from Charon to Pluto (Issue #176)

## Context

Charon's `core/scheduler` is the first stage of the duty pipeline: it resolves beacon-chain duties per epoch, ticks the slot clock, and fans duties out to downstream components (Fetcher, Consensus, DutyDB, etc.) via callbacks. Pluto currently has no scheduler — it's a blocker for end-to-end duty execution. The duty types it produces (`Attester`, `Aggregator`, `Proposer`, `SyncContribution`) need to be the *first* duties Pluto can emit before the rest of the pipeline can be exercised.

Verdict: **port is feasible and can start immediately.** Pluto already has every dependency the scheduler needs (eth2api client, validator cache, deadline subsystem, cluster pubkeys, slot/epoch types, vise metrics, tokio task plumbing). The only foundational fix needed before scheduler code can compile cleanly is a one-line semantic correction to `DutyDefinitionSet`.

## Reference (Charon Go source)

`/home/emlautarom1/Development/Nethermind/charon/core/scheduler/`
- `scheduler.go` (808 lines) — main logic
- `offset.go` (24 lines) — intra-slot duty offsets (`1/3` for `Attester`, `2/3` for `Aggregator`/`SyncContribution`)
- `metrics.go` (87 lines) — Prometheus metrics
- `scheduler_test.go`, `scheduler_internal_test.go`, `testdata/*.golden`

## Step 1 — Fix `DutyDefinitionSet` semantics (prerequisite)

**File:** `crates/core/src/types.rs:411-462`

The current type is `HashMap<DutyType, DutyDefinition<T>>`. Charon's analog (`core/types.go:334`) is `map[PubKey]DutyDefinition` — one definition per validator for a given duty. The scheduler stores duties as `map[Duty]DutyDefinitionSet`, where the outer key already encodes the `DutyType`, so keying the inner map by `DutyType` is wrong.

Change to `HashMap<PubKey, DutyDefinition<T>>` and update method signatures (`get(&PubKey)`, `insert(PubKey, …)`, etc.). The type has exactly one caller (a test in `types.rs:1007-1011`); update it. Verify with `cargo check --workspace` after the change. This mirrors the existing `SignedDataSet<T>(HashMap<PubKey, T>)` at `types.rs:715`, which is already correctly keyed.

## Step 2 — Create the scheduler module

**Location:** `crates/core/src/scheduler/` (new), exposed from `crates/core/src/lib.rs`.

```
crates/core/src/scheduler/
  mod.rs        — Scheduler struct, public API
  offsets.rs    — intra-slot duty offsets (port of offset.go)
  resolve.rs    — resolveAttDuties / resolveProDuties / resolveSyncCommDuties
  ticker.rs     — slot ticker (port of newSlotTicker)
  startup.rs    — waitChainStart, waitBeaconSync
  metrics.rs    — vise metrics (port of metrics.go)
```

### 2a — Type signatures (mirror Charon, idiomatic Rust)

- `pub struct Scheduler { eth2_cl: EthBeaconNodeApiClient, pubkeys: Vec<PubKey>, builder_enabled: bool, … }`
- Cached state behind `Arc<RwLock<…>>`:
  - `duties: HashMap<Duty, DutyDefinitionSet<DutyDefinitionPayload>>`
  - `duties_by_epoch: HashMap<u64, Vec<Duty>>`
  - `resolved_epoch: u64`, `resolving_epoch: u64`
- Subscriber lists: `duty_subs: Vec<Arc<dyn Fn(Duty, DutyDefinitionSet) -> BoxFuture<Result<()>> + Send + Sync>>`, `slot_subs: Vec<…>`.
- Public methods (1:1 with Charon):
  - `Scheduler::new(pubkeys, eth2_cl, builder_enabled)`
  - `subscribe_duties(cb)`, `subscribe_slots(cb)` — must be called before `run`
  - `run(cancel: CancellationToken) -> Result<()>`
  - `get_duty_definition(duty) -> Result<DutyDefinitionSet>`
  - `handle_chain_reorg_event(epoch)` — **always enabled** in Pluto (no featureset gating)

### 2b — Concrete payload type for `DutyDefinition<T>`

Charon uses an interface; in Rust we'll need a concrete enum, e.g.:

```rust
pub enum SchedulerDutyDefinition {
    Attester(AttesterDutyDefinition),  // from eth2api types
    Proposer(ProposerDutyDefinition),
    SyncContribution(SyncCommitteeDutyDefinition),
    // Aggregator reuses the AttesterDutyDefinition payload (per Charon's derivation at scheduler.go:400)
}
```

Source the wire shapes from existing `pluto_eth2api::Get{Attester,Proposer,SyncCommittee}DutiesResponseResponseDatum`.

### 2c — Beacon client access

Per the user decision: keep the concrete `EthBeaconNodeApiClient` (no trait abstraction). All calls go through:
- `client.get_attester_duties(...)` (`eth2api/src/client.rs:1341`)
- `client.get_proposer_duties(...)` (`eth2api/src/client.rs:1368`)
- `client.get_sync_committee_duties(...)` (`eth2api/src/client.rs:1390`)
- `client.get_genesis(...)` for chain-start wait
- `client.fetch_slots_config()` for slot duration / `slots_per_epoch` (`eth2api/src/extensions.rs:273`)
- Node syncing endpoint — verify it exists or add it (Charon uses `eth2Cl.NodeSyncing`).

Use **`ValidatorCache`** (`crates/app/src/eth2wrap/valcache.rs:69`) to mirror Charon's `resolveActiveValidators` / `CompleteValidators` logic — it already filters active validators per epoch and supports `trim()` on epoch boundary.

### 2d — Slot ticker (`ticker.rs`)

Port `newSlotTicker` (scheduler.go:629). Use `tokio::time::sleep_until` with the genesis-time + `slot * slot_duration` formula. Emit `core::Slot { slot, time, slot_duration, slots_per_epoch }` (already defined at `types.rs:763`). For tests, parameterize on a clock source — extend the existing pattern from `crates/app/src/retry.rs` (`time_fn: Arc<dyn Fn() -> DateTime<Utc>>`).

### 2e — Intra-slot offset delays (`offsets.rs`)

Direct port of `offset.go`. Map:

| Duty | Offset |
|------|--------|
| `Attester` | `slot_duration * 1/3` |
| `Aggregator` | `slot_duration * 2/3` |
| `SyncContribution` | `slot_duration * 2/3` |
| `Proposer` | none (fire at slot start) |

### 2f — Resolve logic (`resolve.rs`)

Port `resolveDuties` (scheduler.go:298) and its three sub-functions:
- `resolve_att_duties` — calls `get_attester_duties`, emits paired `DutyAttester` + `DutyAggregator` definitions
- `resolve_pro_duties` — calls `get_proposer_duties`
- `resolve_sync_comm_duties` — calls `get_sync_committee_duties`, expands across all slots in the epoch

Each populates the `duties` cache and `duties_by_epoch` index. Use `expbackoff`-equivalent retry via `tokio_retry` or a small hand-rolled retry loop — keep it inline with how the codebase already does retries.

### 2g — Lifecycle & trimming

- On `run`: `wait_chain_start` → `wait_beacon_sync` → start ticker loop.
- Per slot: emit slot callbacks, then schedule duties asynchronously (`tokio::spawn` per subscriber per duty, after `delay_slot_offset`).
- On epoch boundary: trim duties older than `trim_epoch_offset = 3` (scheduler.go:28).
- Use `CancellationToken` from `tokio-util` (already a workspace dep) instead of Charon's `quit` channel.

### 2h — Metrics (`metrics.rs`)

Port via `vise` (workspace dep, already used in `crates/p2p/src/bandwidth.rs`):
- `slot_gauge`, `epoch_gauge`, `active_vals_gauge`, `skip_counter`
- `duty_counter{type=...}`, `balance_gauge{pubkey=...}`, `status_gauge{pubkey=..., status=...}`

## Step 3 — Tests

Per user decision: **port unit tests using `testcontainers`** to drive against a real beacon node, following the pattern in `crates/eth2api/src/integration.rs:1-80` (`BeaconNodeContainer::shared()`).

Test files to create under `crates/core/src/scheduler/`:
- `mod.rs` `#[cfg(test)] mod tests` — ports of `scheduler_internal_test.go`: `TestResolveAttDuties`, `TestResolveProDuties`, `TestResolveSyncCommDuties`, `TestResolvingEpoch`.
- `tests/integration.rs` (or a sibling integration module) — ports of `scheduler_test.go`: `TestSchedulerDuties`, `TestScheduler_GetDuty`, `TestSchedulerWait`, `TestNoActive`, `TestHandleChainReorgEvent`. Skip `TestIntegration` itself (it's already a flag-gated live-network test in Go and is covered by the testcontainer setup).

Translate the `*.golden` JSON files from `charon/core/scheduler/testdata/` into Rust fixtures (either inline `serde_json::json!` or check the JSON files in alongside the test module and read via `include_str!`).

## Critical files

**Modify (prerequisite):**
- `crates/core/src/types.rs` — re-key `DutyDefinitionSet<T>` to `HashMap<PubKey, DutyDefinition<T>>` (lines 411–462) + fix test at 1007–1011.

**Create:**
- `crates/core/src/scheduler/` (full new module as outlined above).

**Touch:**
- `crates/core/src/lib.rs` — `pub mod scheduler;`
- `crates/core/Cargo.toml` — add deps as needed (`tokio-util` for `CancellationToken`, `vise` for metrics, possibly `tokio-retry`).

## Reused existing infrastructure

- `pluto_core::types::{Duty, DutyType, PubKey, Slot, SlotNumber, DutyDefinition, DutyDefinitionSet}` — `crates/core/src/types.rs`
- `pluto_eth2api::EthBeaconNodeApiClient` + `extensions::{fetch_genesis_time, fetch_slots_config}` — `crates/eth2api/src/`
- `pluto_app::eth2wrap::valcache::{ValidatorCache, ActiveValidators}` — `crates/app/src/eth2wrap/valcache.rs`
- `pluto_core::deadline::{Deadliner, DeadlinerTask}` — `crates/core/src/deadline/mod.rs` (consumer side; scheduler feeds it)
- `pluto_cluster::lock::Lock` — for sourcing the initial `pubkeys: Vec<PubKey>`
- `tokio_util::sync::CancellationToken` — shutdown
- `vise` — metrics
- Testcontainer pattern in `crates/eth2api/src/integration.rs` — beacon node fixture for tests

## Out of scope (deferred)

- **SSE listener** that calls `handle_chain_reorg_event` — the method is implemented, but the SSE source isn't wired in this PR (no SSE infra in Pluto yet).
- **`featureset` system** — not needed since we always enable reorg handling.
- **`schedSlotFunc`** — Charon test-only hook; reproduce via test-side closure injection if needed, otherwise drop.

## Verification

1. `cargo +nightly fmt --all --check`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
3. `cargo test --workspace --all-features` — ensures the `DutyDefinitionSet` re-key doesn't break anything else and scheduler unit tests pass.
4. Scheduler integration tests via testcontainer beacon node: `cargo test -p pluto-core scheduler::` — verify duty resolution against a real BN matches expected slot/validator counts.
5. Manual end-to-end: wire the scheduler in `crates/app/src/lib.rs` against a devnet beacon node, subscribe a logging callback, and confirm `DutyAttester` / `DutyProposer` events fire at the expected intra-slot offsets across two epochs.
