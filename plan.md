# DKG Interoperability Plan — Pluto ↔ Charon

## Status

Branch: `bohdan/dkg-final`

Goal: make a mixed DKG ceremony work with Pluto and Charon nodes participating together.

---

## Root Cause Analysis

### Bug 1 — Wrong sync protocol version (FIXED)

**File:** `crates/dkg/src/node.rs:158`

**Problem:** The sync client was sending the *cluster schema version* (`definition.version`, e.g. `v1.10`) instead of the *node software minor version* (`v1.7`).

Charon's sync server validates the version field first. A version mismatch causes "invalid sync request" before the signature is ever checked — this is the "invalid signature for definition" error the user observed (because version rejection fires before signature verification in `validate_request_with_public_key`).

**Fix applied:**
```rust
// Before (wrong — cluster schema version)
let sync_version = SemVer::parse(&definition.version)
    .expect("validated cluster definition version should parse")
    .to_minor();

// After (correct — node software minor version, matches Charon's version.Version.Minor())
let sync_version = VERSION.to_minor();  // → "v1.7"
```

Reference: `charon/dkg/dkg.go:492` — `minorVersion := version.Version.Minor()`.

---

### Bug 2 — Empty bytes serialized as `"0x"` instead of `""` (FIXED)

**File:** `crates/ssz/src/serde_utils.rs`

**Problem:** `encode_0x_hex` was returning `"0x"` for empty byte slices. Go's `to0xHex` in `charon/cluster/helpers.go` returns `""` for empty slices. This could cause JSON deserialization failures on Charon's side for optional byte fields.

**Fix applied:**
```rust
pub fn encode_0x_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    format!("0x{}", hex::encode(bytes))
}
```

---

### Bug 3 — Relay routing too slow / before relay ready (FIXED)

**File:** `crates/p2p/src/relay.rs`

**Problem:** `RelayRouter` was polling every 60s with a 10s initial delay, and attempting to route through relays before they were fully ready. This meant Pluto nodes were not being routed to each other through the relay in reasonable time.

**Fixes applied:**
- `RELAY_ROUTER_INTERVAL`: 60s → 5s
- `RELAY_ROUTER_INITIAL_DELAY`: 10s → 1s
- Added `RELAY_READY_DELAY = 2s`: wait at least 2s after relay connection established before routing peers through it
- Track relay connection timestamps in `connected_relays: HashMap<PeerId, Instant>`
- `relay_ready()` checks `elapsed() >= RELAY_READY_DELAY`
- `MutableRelayReservation` dials relay directly, then listens on circuit after `ConnectionEstablished`
- Added `PeerCondition::DisconnectedAndNotDialing` to avoid duplicate dials

---

### Cleanup — ENR debug artifact (FIXED)

**File:** `crates/dkg/src/dkg.rs`

Removed a stray ENR list comment appended to the end of the file after the closing `}` of the test module.

---

## DKG Ceremony Management Tool

### Goal

A script (or small CLI) that runs a complete DKG ceremony end-to-end with a configurable mix of Pluto and Charon nodes, without manual setup between runs.

### Architecture

```
scripts/dkg-runner/
  run.sh          # Main entry point
  setup.sh        # Creates cluster definition via charon create dkg
  start-nodes.sh  # Starts N Pluto + M Charon nodes in parallel
  collect.sh      # Collects logs and outputs
  reset.sh        # Cleans up between runs
```

### What it does

1. **Setup**: `charon create dkg --nodes=N --threshold=T` → generates `cluster-definition.json`
2. **Start relay**: Use a local or public Obol relay (configurable via `RELAY_URL`)
3. **Start nodes**: For each node slot, start either a Pluto or Charon process:
   - Pluto: `pluto dkg --definition-file=... --data-dir=node-N/`
   - Charon: `charon dkg --definition-file=... --data-dir=node-N/`
4. **Monitor**: Tail all log files, detect ceremony completion or failure
5. **Collect**: Copy `keystore-*.json` outputs, print summary
6. **Reset**: `rm -rf node-*/` to allow a fresh run

### Configuration (env vars)

| Var | Default | Description |
|-----|---------|-------------|
| `NODES` | `4` | Total node count |
| `THRESHOLD` | `3` | Signing threshold |
| `PLUTO_NODES` | `2` | How many slots use Pluto |
| `CHARON_NODES` | `2` | How many slots use Charon |
| `RELAY_URL` | `https://relay.obol.tech` | Relay ENR endpoint |
| `TIMEOUT` | `120` | Seconds before aborting |
| `PLUTO_BIN` | `./target/debug/pluto` | Path to Pluto binary |
| `CHARON_BIN` | `charon` | Path to Charon binary |

### Usage

```bash
# Pure Pluto (4 nodes)
PLUTO_NODES=4 CHARON_NODES=0 ./scripts/dkg-runner/run.sh

# Mixed (2 Pluto + 2 Charon)
PLUTO_NODES=2 CHARON_NODES=2 ./scripts/dkg-runner/run.sh

# Run multiple times
for i in $(seq 1 5); do ./scripts/dkg-runner/run.sh; done
```

---

## Next Steps

- [ ] **Empirical validation**: Run the tool with 2 Pluto + 2 Charon nodes and observe logs
- [ ] **Verify relay logic**: Compare `MutableRelayReservation` behavior against Charon's `p2p/relay.go`
- [ ] **Verify signature logic**: Confirm `sign_definition_hash` (libp2p `Keypair::sign`) matches Charon's `(*Secp256k1PrivateKey).Sign` — both use SHA-256 internally
- [ ] **FROST round compatibility**: Verify `FrostP2PBehaviour` message format matches Charon's frost round-1 P2P messages
- [ ] **Parsigex compatibility**: Verify `ParsexBehaviour` wire format matches Charon's parsigex
- [ ] **Integration test**: Add a `#[tokio::test]` that runs a simulated 4-node DKG with all-Pluto nodes as a smoke test

---

## Reference

- Go source: `charon/` (in this repo)
- Key Go files for DKG:
  - `charon/dkg/dkg.go` — main ceremony orchestration
  - `charon/dkg/sync/server.go` — sync server + request validation
  - `charon/app/version/version.go` — version constants
  - `charon/cluster/helpers.go` — `to0xHex` and cluster utilities
  - `charon/p2p/relay.go` — relay connection logic
