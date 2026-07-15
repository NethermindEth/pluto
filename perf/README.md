# Pluto vs Charon performance harness

Automated performance comparison between Pluto (this repo) and the Go Charon
implementation. One command runs matching workloads on both sides, normalizes
the results, and renders a report that flags every pair where Pluto is slower
than Charon (`ratio > 1.15` → `SUBOPTIMAL`) — the work queue for optimization.

## Quick start

```bash
# Requires: the charon Go source at ./charon (or CHARON_SRC=...), Go with
# network access (GOTOOLCHAIN=auto downloads the pinned toolchain), python3.
# Tier 3 additionally requires hyperfine.

./perf/run.sh --tier 12          # tiers 1+2, full sample counts
./perf/run.sh --tier 1 --quick   # fast sanity pass
./perf/run.sh --tier all         # everything incl. process-level (tier 3)
```

Outputs land in `perf/out/` (gitignored):

- `report.md` — the human-readable comparison, sorted by pluto/charon ratio,
  with a "Work on these" section listing SUBOPTIMAL pairs.
- `results.json` — machine-readable results (`{meta, results[]}`), suitable
  for committing as `perf/baseline.json` to gate regressions.
- `go-bench.txt`, `hyperfine/*.json`, `dkg-times.json`, `cli-extra.json` — raw
  inputs.

## Tiers

| Tier | What | How |
|---|---|---|
| 1 | Pure compute: BLS tbls (blst vs herumi), secp256k1, FROST DKG rounds, SSZ encode/decode/hash, protobuf | criterion benches in `crates/*/benches/` vs `go test -bench` in `perf/go-bench/` |
| 2 | In-memory components: full QBFT consensus instance (spawn → all decided), in-memory FROST DKG ceremony (Rust-only) | same, using in-process transports on both sides |
| 3 | Process level: `create enr` / `create cluster` wall time (hyperfine), full DKG ceremony via `scripts/dkg-runner`, peak RSS | `perf/cli-matrix.sh`, `perf/dkg-e2e.sh` |

Tier 3's DKG ceremony needs relay connectivity (dkg-runner's default relay or
`RELAY_URL=...`); when it fails, run.sh logs a warning and the report simply
omits those rows.

## How pairing works

`perf/pairs.json` maps a canonical pair id (also the Rust criterion benchmark
id) to the Go benchmark name (`BenchmarkTier1TblsSign` → `Tier1TblsSign`).
Tier 3 inputs carry their own ids. Workloads are kept byte-identical across
languages: shared binary fixtures live in `perf/fixtures/` (generated once by
the Go side: `WRITE_FIXTURES=1 go test -run TestGenFixtures .` in
`perf/go-bench/`), and each Rust bench asserts a re-encode round-trip against
the fixture before timing, so a workload mismatch fails loudly instead of
comparing different work.

Some pairs intentionally compare different backends doing the same production
job (noted in `workload`), e.g. `tier1/frost/partial_sign` pits Pluto's
kryptology-compatible blst signing against charon's herumi tbls signing —
that is what actually runs on each side during a mixed ceremony.

## Adding a pair

1. Add the Rust bench (`crates/<crate>/benches/`, criterion id
   `tierN/<area>/<name>`; copy the `[[bench]]`/`[lib] bench = false` pattern).
2. Add the Go bench in `perf/go-bench/` named `BenchmarkTierN<Area><Name>`.
3. Add the mapping to `perf/pairs.json`.
4. If the workload needs a fixture, extend `TestGenFixtures` and assert the
   round-trip on the Rust side.

## Build configs compared

Benchmarks compare **as-shipped** configurations: Rust `--release` with the
workspace defaults (currently no LTO, `codegen-units = 16`) and Go's
`-trimpath -ldflags "-s -w"`. Tuning the Rust release profile is itself a
candidate optimization to evaluate with this harness.

## CI

`.github/workflows/perf.yml` runs tiers 1+2 nightly and on demand
(`workflow_dispatch`), pinning charon to the version in the workflow's
`CHARON_VERSION`. The report is appended to the job summary and uploaded as an
artifact. Regression gating: pass `--baseline perf/baseline.json` (a committed
blessed `results.json`); `render.py` exits 2 when any pair's ratio worsens
more than 10%, and refuses to compare baselines across differing os/arch.
Cross-language `SUBOPTIMAL` flags alone never fail CI — they are a work
queue, not a gate.

## Notes / limitations

- `bench-util` cargo features on `pluto-core` and `pluto-dkg` expose internal
  modules and in-memory harnesses to the benches. Never enable in production.
- `pluto run` does not yet expose a Prometheus `/metrics` endpoint (the relay
  does), so live-cluster latency comparison via the charon-mirroring
  `core_*`/`p2p_*` metrics is not wired here yet.
- Numbers are per-platform (blst/herumi both ship per-arch assembly); do not
  compare arm64-mac results against linux baselines.
