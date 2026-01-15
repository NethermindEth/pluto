# Peerinfo Example

Demonstrates the peerinfo protocol with mDNS auto-discovery.

## Setup

### Using Nix (recommended)

```bash
nix develop
```

### Manual

Ensure you have:

- Rust (stable + nightly for fmt)
- protobuf compiler (`protoc`)

## Creating a cluster

For now we use simple approach by creating cluster in charon and taking private keys from the generated nodes.

### Building charon

So to do this you need to clone [charon repository](https://github.com/ObolNetwork/charon.git)

Then, in the cloned repository build charon:

```bash
make charon
```

Output binary (`charon`) will be put in the project's root directory and will be accessible via `./charon <args>`.
Now, you have everything needed to create test cluster.

### Creating cluster configuration

Creating a cluster could be done by simply running:

```bash
./charon create cluster --nodes 3 --network mainnet --num-validators 1 --cluster-dir ./test-cluster --insecure-keys --fee-recipient-addresses 0x0000000000000000000000000000000000000000 --withdrawal-addresses 0x0000000000000000000000000000000000000000
```

This command will initialize testing cluster with 3 nodes and 1 validator and put output artifacts in the `./test-cluster` folder. Each node configuration will have separate subfolder in the format of node<NODE_NUMBER> (i.e. node1, node2, node3 etc.).

Next, thing we will do is to actually run first node:

```bash
./charon run --simnet-beacon-mock --no-verify --nickname=charon-1 --lock-file=test-cluster/node0/cluster-lock.json --private-key-file=test-cluster/node0/charon-enr-private-key --p2p-tcp-address=0.0.0.0:3610 --validator-api-address=0.0.0.0:3680 --monitoring-address=0.0.0.0:9464 --log-level=debug
```

### Initializing the peerinfo example

In order to connect to the `node0` we need to initialize our example with 2 node profiles (node1, node2).

```bash
make init-peerinfo node1 KEY=<PRIVATE_KEY_NODE_1>
make init-peerinfo node1 KEY=<PRIVATE_KEY_NODE_2>
```

This will initialize data-dirs for two pluto nodes.

### Running pluto's nodes

To run the node you will need the following commands in different terminals:

```bash
make peerinfo node1 /ip4/127.0.0.1/tcp/3610
```

```bash
make peerinfo node2 /ip4/127.0.0.1/tcp/3610
```

`/ip4/127.0.0.1/tcp/3610` is tcp address of charon's node in [multiaddr format](https://multiformats.io/multiaddr/).

### Working with results

Charon node is configured to send `peerinfo` every one minute and you will be able to see corresponding logs in the terminal.

On charon's side you can track the by accessing metrics endpoint:

```bash
curl 0.0.0.0:9464/metrics | grep app_peerinfo
```

For pluto:

`node1`:

```bash
curl 0.0.0.0:9465/metrics | grep app_peerinfo
```

`node2`:

```bash
curl 0.0.0.0:9466/metrics | grep app_peerinfo
```

### Running grafana locally

To run grafana we use `docker-compose`. All infra files located at `test-infra` folder.

To run it use this command:

```bash
cd test-infra
docker-compose up
```

And grafana will be accessible via `http://localhost:3000`.

> Note, that you may need to add prometheus as a data source