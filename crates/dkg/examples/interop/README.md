# Pluto + Charon Sync Interop Demo

Manual 5-terminal interop demo for `dkg/sync`.

Pre-step:
- generate shared fixture once

Runtime topology:
- terminal 1: Pluto relay
- terminal 2: Pluto node 0
- terminal 3: Pluto node 1
- terminal 4: Charon node 2
- terminal 5: Charon node 3

Assumptions:
- relay URL: `http://127.0.0.1:8888`
- shared fixture dir: `/tmp/pluto-sync-interop`

Set these once in every terminal:

```bash
PLUTO_CODE_DIR=/path/to/charon-rs
CHARON_CODE_DIR=/path/to/charon
```

## Pre-step: Build Charon And Create Shared Fixture

Run:

```bash
cd "$CHARON_CODE_DIR"
go build -o /tmp/charon .
/tmp/charon create cluster \
  --cluster-dir /tmp/pluto-sync-interop \
  --nodes 4 \
  --num-validators 1 \
  --network holesky \
  --insecure-keys \
  --fee-recipient-addresses 0x000000000000000000000000000000000000dEaD \
  --withdrawal-addresses 0x000000000000000000000000000000000000dEaD
```

This creates:
- `/tmp/pluto-sync-interop/node0`
- `/tmp/pluto-sync-interop/node1`
- `/tmp/pluto-sync-interop/node2`
- `/tmp/pluto-sync-interop/node3`

After this finishes, close that terminal. The runtime demo uses 5 terminals total.

## Terminal 1: Start Relay

Run from Pluto repo root:

```bash
cd "$PLUTO_CODE_DIR"
cargo run -p pluto-relay-server --example relay_server
```

Leave it running.

## Terminal 2: Start Pluto Node 0

Run from Pluto repo root:

```bash
cd "$PLUTO_CODE_DIR"
cargo run -p pluto-dkg --example sync -- \
  --relays http://127.0.0.1:8888 \
  --data-dir /tmp/pluto-sync-interop/node0
```

## Terminal 3: Start Pluto Node 1

Run from Pluto repo root:

```bash
cd "$PLUTO_CODE_DIR"
cargo run -p pluto-dkg --example sync -- \
  --relays http://127.0.0.1:8888 \
  --data-dir /tmp/pluto-sync-interop/node1
```

## Terminal 4: Start Charon Node 2

Run from Pluto repo root:

```bash
cd "$PLUTO_CODE_DIR"
CHARON_DIR="$CHARON_CODE_DIR" \
bash ./crates/dkg/examples/interop/charon_sync_demo.sh \
  --data-dir /tmp/pluto-sync-interop/node2 \
  --relay-url http://127.0.0.1:8888
```

## Terminal 5: Start Charon Node 3

Run from Pluto repo root:

```bash
cd "$PLUTO_CODE_DIR"
CHARON_DIR="$CHARON_CODE_DIR" \
bash ./crates/dkg/examples/interop/charon_sync_demo.sh \
  --data-dir /tmp/pluto-sync-interop/node3 \
  --relay-url http://127.0.0.1:8888
```

## Recommended Startup Order

1. Run the pre-step once to create the fixture.
2. Start relay in terminal 1.
3. Start Pluto node 0 in terminal 2.
4. Start Pluto node 1 in terminal 3.
5. Start Charon node 2 in terminal 4.
6. Start Charon node 3 in terminal 5.

## Success Signals

On Pluto nodes:
- `Relay reservation accepted`
- `Connection established`
- `All sync clients connected`
- `Sync step reached`
- `Sync demo is now idling until Ctrl+C`

On Charon nodes:
- `Started charon sync demo`
- `Waiting for peers to connect`
- `All peers connected`
- `Sync step reached local_node=... step=1`
- `Sync step reached local_node=... step=2`
- `Sync demo is now idling until Ctrl+C`

## Stop The Demo

Press `Ctrl+C` in any node terminal.
