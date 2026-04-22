# Peerinfo Example

Demonstrates the peerinfo protocol with mDNS auto-discovery.

## Prerequisites

> **Note:** This example uses two projects: **Pluto** and **Charon**. Charon is used only for running the `charon run` command to start the distributed validator middleware node. Pluto handles the peer discovery and information sharing.
We'll refer to Pluto directory as `$PLUTO_PATH` in the following steps.


## Running Grafana Locally

Before running the nodes, start the monitoring infrastructure. We use `docker compose` to run both Prometheus (for metrics) and Loki (for logs).

From the project root:

```bash
docker compose -f test-infra/docker-compose.yml up -d
```

Grafana will be accessible at `http://localhost:3000`.

> Note: You may need to add Prometheus as a data source in Grafana.

## Creating a Cluster

For now we use a simple approach by creating a cluster in charon and taking private keys from the generated nodes.

### Creating Cluster Configuration

Create a cluster by running a commond in Pluto:

```bash
cargo run -- create cluster --nodes 3 --network mainnet --num-validators 1 --cluster-dir ./test-cluster --insecure-keys --fee-recipient-addresses 0x0000000000000000000000000000000000000000 --withdrawal-addresses 0x0000000000000000000000000000000000000000
```

This command initializes a testing cluster with 3 nodes and 1 validator, putting output artifacts in the `./test-cluster` folder. Each node configuration has a separate subfolder in the format `node<NODE_NUMBER>` (i.e. node0, node1, node2 etc.).

### Building Charon

Clone the [charon repository](https://github.com/ObolNetwork/charon.git) at tag `v1.7.1`:

```bash
git clone --branch v1.7.1 https://github.com/ObolNetwork/charon.git
cd charon
```

Build charon:

```bash
make charon
```

The output binary (`charon`) will be in the project's root directory and accessible via `./charon <args>`.

### Running the Charon Node

Run the first charon node (`node0`):

```bash
./charon run --simnet-beacon-mock --no-verify --nickname=node0 --lock-file=$PLUTO_PATH/test-cluster/node0/cluster-lock.json --private-key-file=$PLUTO_PATH/test-cluster/node0/charon-enr-private-key --p2p-tcp-address=0.0.0.0:3610 --validator-api-address=0.0.0.0:3680 --monitoring-address=0.0.0.0:9464 --log-level=debug
```

**Flag explanations:**

- `--simnet-beacon-mock`: Uses a mock beacon node for testing without a real Ethereum beacon chain
- `--no-verify`: Skips signature verification (for testing purposes only)
- `--validator-api-address`: Address for the validator client API endpoint

### Running Pluto Nodes

> **Important:** Start the Charon node before starting Pluto nodes, otherwise Pluto will hang waiting for the connection.

> **Note:** In this mixed setup (1 Charon node + 2 Pluto peers), the Charon node will log consensus timeout errors like `Permanent failure calling consensus/participate: consensus timeout`. This is expected because Charon requires a quorum of nodes (2 out of 3) to reach consensus, but only 1 is a full Charon node. These errors do not affect the peerinfo protocol test—peer discovery and information exchange work correctly regardless.

Run `node1` in a separate terminal, pluto directory:

```bash
cargo run -p pluto-peerinfo --example peerinfo -- \
    --port 4001 \
    --nickname node1 \
    --data-dir test-cluster/node1 \
    --metrics-port 9465 \
    --loki-url http://localhost:3100 \
    --loki-label cluster=peerinfo-example \
    --dial /ip4/127.0.0.1/tcp/3610
```

Run `node2` in another terminal:

```bash
cargo run -p pluto-peerinfo --example peerinfo -- \
    --port 4002 \
    --nickname node2 \
    --data-dir test-cluster/node2 \
    --metrics-port 9466 \
    --loki-url http://localhost:3100 \
    --loki-label cluster=peerinfo-example \
    --dial /ip4/127.0.0.1/tcp/3610
```

**Notes on `--data-dir`:**

- The `--data-dir` argument specifies the node directory created by `create cluster`
- The directory should contain:
  - `charon-enr-private-key`: The node's private key (required)
  - `cluster-lock.json`: The cluster lock file (optional, but needed for proper peer identification)
- When `cluster-lock.json` is present, the lock hash and peer IDs are extracted from it
- This enables proper peer identification and lock hash verification with the Charon node

**Notes on `--dial`:**

- The `--dial` argument is optional. If not provided, nodes will rely on mDNS auto-discovery.
- Multiple addresses can be specified by repeating `--dial`: `--dial /ip4/.../tcp/3610 --dial /ip4/.../tcp/3611`
- Addresses use [multiaddr format](https://multiformats.io/multiaddr/) (e.g., `/ip4/127.0.0.1/tcp/3610`).

### Working with Results

Pluto node is configured to send `peerinfo` every 5 seconds and you will be able to see corresponding logs in the terminal.

On charon's side you can track the metrics endpoint by:

```bash
curl -s 127.0.0.1:9464/metrics | grep app_peerinfo
```

For Pluto nodes:

`node1`:

```bash
curl -s 127.0.0.1:9465/metrics | grep app_peerinfo
```

`node2`:

```bash
curl -s 127.0.0.1:9466/metrics | grep app_peerinfo
```
