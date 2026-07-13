# Pluto Compose

> Run, test, and debug a developer-focussed insecure local pluto/charon cluster using docker compose

This is a port of charon's `[testutil/compose](https://github.com/ObolNetwork/charon/tree/main/testutil/compose)`
(pinned at `v1.7.1`, the pluto parity reference) with one extra axis: each node in the
cluster can run either **charon** or **pluto**, so clusters of N charon + M pluto nodes
can be composed for cross-implementation testing.

Compose is a tool that generates `docker-compose.yml` files such that different clusters
can be created and run. The aim is for developers to be able to debug features and check
functionality of clusters on their local machines.

The `compose` command should be executed in sequential steps:

1. `compose new`: Creates a new config.json that defines what will be composed.
2. `compose define`: Creates a docker-compose.yml that executes `create dkg` if keygen==dkg.
3. `compose lock`: Creates a docker-compose.yml that executes `create cluster` or `dkg`.
4. `compose run`: Creates a docker-compose.yml that executes `run`.

The `compose` command also includes some convenience functions.

- `compose clean`: Cleans the compose directory of existing files.
- `compose auto`: Runs `compose define && compose lock && compose run`.

Note that compose automatically runs `docker compose up` at the end of each command. This can be disabled via `--up=false`.

## Node implementations

Node implementations are assigned round-robin from `--node-impls` (like validator types):

```
compose new --node-impls=charon                # all charon (default)
compose new --node-impls=pluto                 # all pluto
compose new --nodes=4 --node-impls=charon,charon,pluto,pluto  # 2 charon + 2 pluto
```

- Charon nodes run `obolnetwork/charon:{tag}` (default `latest`, or `local` built from
`CHARON_REPO` with `--build-local`).
- Pluto nodes run `pluto:{tag}` (default `local`), built automatically from the repo
root `Dockerfile` during the define step. This requires the `PLUTO_REPO` env var
pointing at the pluto repo.
- `--keygen-impl` selects which implementation runs the single-container keygen steps
(`create cluster` / `create dkg`); it defaults to node0's implementation.
- The relay always runs the charon node-base image.

Pluto accepts `CHARON_*` env vars and charon-compatible flags by design (CLI parity),
so the generated docker-compose.yml services are identical for both implementations
apart from the image. All node roles are supported for both implementations: keygen
(`create cluster`, `create dkg`, `dkg`) and `run`.

Implementation names are validated when configs are written and loaded; anything
other than `charon` or `pluto` is rejected.

## Usage Examples

Install the `compose` binary:

```
# From inside the pluto repo
go install ./test-infra/compose/compose

# If `which compose` fails, then fix your environment: `export PATH=$PATH:$(go env GOPATH)/bin`. Or see https://go.dev/doc/gopath_code
```

Create a pluto compose workspace folder:

```
cd /tmp
mkdir pluto-compose
cd pluto-compose
```

Create the default cluster:

```
export PLUTO_REPO=/path/to/pluto
compose clean && compose new --node-impls=pluto && compose define && compose lock && compose run
```

Monitor the cluster via `grafana`:

```
open http://localhost:3000/d/charon_overview_dashboard/charon-overview  # Open Grafana simnet dashboard
```

Creating a DKG based all-pluto cluster:

```
export PLUTO_REPO=/path/to/pluto
compose new --keygen=dkg --node-impls=pluto
compose auto
```

Creating a mixed cluster (2 charon + 2 pluto, forcing both implementations
to participate in every duty at the default 3-of-4 threshold):

```
export PLUTO_REPO=/path/to/pluto
compose new --nodes=4 --node-impls=charon,charon,pluto,pluto
compose auto
```

## Smoke tests

`smoke/smoke_test.go` mirrors charon's compose smoke tests: each scenario generates
and runs a full cluster with a mock beacon node (simnet), while a Prometheus container
evaluates the generated alert rules (see `writeAlertRules` in `define.go`). A scenario
fails if any alert fires.

Alert semantics: collection starts once Prometheus answers its rules API. For the
next 60 seconds (the warmup window) exactly three known cold-start transients are
tolerated and must self-resolve — `Error Log Rate` (one consensus-timeout error per
node at the first epoch boundary, before the validator mock submits duties),
`Warn Log Rate` (charon's app-start warning burst), and `Broadcast Duty Rate` (no
duties broadcast before the p2p mesh forms). Any other alert fires the scenario
immediately, warmup or not, and so does anything still firing after the warmup.

```
cd test-infra/compose

# Pluto scenarios only (builds pluto:local from PLUTO_REPO; relay and
# pluto_keygen_create runtime nodes pull obolnetwork/charon:v1.7.1):
PLUTO_REPO=$(git rev-parse --show-toplevel) go test ./smoke -v -integration -timeout=35m \
  -run 'TestSmoke/(pluto_keygen_create|all_pluto|mixed_2_charon_2_pluto|pluto_dkg)$'

# Full matrix (pluto + charon-only scenarios):
PLUTO_REPO=$(git rev-parse --show-toplevel) go test ./smoke -v -integration -timeout=35m

# Keep docker-compose logs per scenario:
go test ./smoke -v -integration -timeout=35m -log-dir=.
```

Scenarios that involve pluto (`pluto_keygen_create`, `all_pluto`,
`mixed_2_charon_2_pluto`, `pluto_dkg`) skip when the `PLUTO_REPO` env var is unset;
everything else always runs. `-timeout=35m` covers the full matrix (each scenario is
bounded by its own 2–3 minute alert window plus image builds); the Go default of 10m
is not enough.

All smoke scenarios run the mock validator client. Real VCs cannot pass the alert
gate against charon v1.7.1's beaconmock: it reports `head_slot: "1"` from
`/eth/v1/node/syncing`, so e.g. lighthouse permanently treats the beacon node as
unsynced and performs no duties, starving the cluster below its signing threshold.
(Upstream charon runs lighthouse in these scenarios but its alert collector matches
a Prometheus state that never occurs, so nothing was ever gated.) The real-VC
services still work for manual clusters via `compose new --validator-types`.

## Versioning

Charon is pinned to the pluto parity reference (`v1.7.1`): both the Go library in
`go.mod` and the docker image tag used by smoke tests. The two `replace` directives in
`go.mod` are copied from charon's own `go.mod` (Go does not propagate a dependency's
replaces) and must be kept in sync when bumping charon. Bump deliberately alongside the
parity target, not to track charon main.