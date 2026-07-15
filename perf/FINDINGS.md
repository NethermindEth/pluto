# Pluto vs Charon — initial performance findings

Date: 2026-07-15 · Host: Apple M3 Pro (darwin/arm64) · rustc 1.95.0 · go 1.25 (charon v1.7.1)
Produced by `./perf/run.sh` (see `perf/README.md`). Numbers are medians; raw
data in `perf/out/`. Ratios are pluto/charon — above 1.00x means Pluto is
slower.

## TL;DR

Pluto is **faster than Charon on most crypto and serialization hot paths**
(BLS sign/verify via blst, FROST DKG rounds up to 5x, protobuf, secp256k1
verify/recover, `create enr`/`create cluster`, 2.6x smaller peak RSS, DKG
ceremony wall-time at parity). The suboptimal areas cluster into **five root
causes**, ordered by duty-hot-path impact:

| # | Area | Ratio | On duty hot path? |
|---|---|---|---|
| 1 | QBFT consensus instance (spawn→decide) | 3.7–10x | yes — every duty |
| 2 | BLS threshold aggregate (sigagg) | 1.2–1.35x | yes — every duty |
| 3 | SSZ encode (attestation, proposal) | 3–4x | yes — every consensus msg |
| 4 | Shamir split / recover secret | 2.3–3.7x | no — ceremony only |
| 5 | scrypt keystore encryption / k1 sign | 2.4x / 1.8x | no — ceremony / p2p setup |

## Findings in detail

### 1. QBFT: 380µs vs 40µs (4 nodes), 712µs vs 195µs (10 nodes) — 3.7–10x

`tier2/qbft/decide_*`. Same in-memory topology on both sides (identical
transport shape, never-firing timers, i64 values). Root causes observed in
`crates/core/src/qbft/mod.rs`:

- **OS thread per participant** vs Go goroutines: Pluto's `qbft::run` is a
  blocking function; the consensus wiring spawns threads per instance. Thread
  spawn + crossbeam channel wakeups dominate the 4-node case.
- **50ms cancellation polling** (`CANCELLATION_POLL_INTERVAL`, used as
  `default(...)` arms in both `select!` loops at mod.rs:473/671 and 745/786):
  instance shutdown latency is up to 50ms vs Go's immediate `ctx.Done()`.
  This did not affect the decide-latency numbers (teardown excluded) but
  delays instance cleanup and holds threads/memory ~50ms longer per duty.
- Absolute numbers are still far below consensus timeouts (~1s), so the
  practical impact per duty is modest — but at scale (many validators, many
  concurrent instances) thread churn adds up.

Suggested work: reuse a small worker pool or async task per instance instead
of dedicated threads; replace cancellation polling with a channel-based token
that can participate in `select!` directly.

### 2. BLS threshold aggregate: 403µs vs 300µs (3-of-4), 947µs vs 792µs (7-of-10) — 1.2–1.35x

`tier1/tbls/threshold_aggregate/*` and `tier1/frost/aggregate`. This runs in
`sigagg` for **every duty**. Root causes in
`crates/crypto/src/blst_impl.rs::lagrange_interpolate_signature` (line 352):

- Each partial goes through `BlstSignature::from_bytes` (compressed
  deserialization + validation) per call, then `signature_mult` round-trips
  projective→affine per share before the additions.
- Scalar mults are done one-by-one; blst offers Pippenger multi-scalar
  multiplication (`blst_p2s_mult_pippenger`) which wins even at 3–10 points.

Interestingly Pluto's raw BLS sign/verify beats herumi by 1.4–1.7x, so the gap
is entirely in the interpolation plumbing, not blst itself.

### 3. SSZ encode: attestation 193ns vs 46ns (4.2x), proposal 1.16µs vs 328ns (3.5x)

`tier1/ssz/att_encode`, `tier1/ssz/proposal_encode` (+decode at 1.9x).
Encoding runs for every consensus value and parsigex exchange. Root causes in
`crates/core/src/ssz_codec.rs`:

- `as_ssz_bytes()` (ethereum_ssz) starts from an empty `Vec` and grows it;
  Go's fastssz generates `MarshalSSZTo` with the exact size preallocated.
- `encode_versioned_signed_proposal` (ssz_codec.rs:427) encodes the inner
  block into its own `Vec`, then copies it into a second header-prefixed
  buffer — a full extra allocation + copy per message.

Suggested work: compute `ssz_bytes_len()` up front and encode into one
right-sized buffer; encode the inner block directly into the output buffer
after the header. `att_hash_root` (1.4–1.5x, tree_hash vs fastssz) is lower
priority.

### 4. Shamir split / recover: 2.3–3.7x (ceremony-only)

`tier1/tbls/threshold_split/*`, `tier1/tbls/recover_secret/*` (µs-scale,
runs only during `create cluster`/DKG). Likely the same per-op
serialize/deserialize round-trips through compressed bytes in `blst_impl.rs`
polynomial evaluation. Low priority; fix alongside finding 2.

### 5. Process-level: secure keystores 2.4x, k1 sign 1.8x

- `tier3/cli/create_cluster_4_secure`: 321ms vs 134ms. Scrypt params are
  identical on both sides (n=2^18, verified in
  `crates/eth2util/src/keystore/keystorev4.rs` vs
  `charon/eth2util/keystore/keystore.go`), so this is the RustCrypto `scrypt`
  crate being slower than Go's `x/crypto/scrypt` (no SIMD salsa20/8 core).
  Options: SIMD-enabled scrypt implementation, or parallelize keystore
  encryption across validators (charon encrypts sequentially too — easy win).
- `tier1/k1/sign`: 60–64µs vs 33µs — k256's base-point multiplication is
  slower than decred's precomputed-table implementation (verify/recover are
  *faster* in k256, so it's specifically sign). Used for ENR/p2p signatures,
  not duty signing. Option: `secp256k1` (libsecp C bindings) for signing, or
  accept.

### Build config: thin LTO + codegen-units=1 experiment

Applied to the bench profile only and re-measured: **~6–12% improvement on
pure-Rust paths** (ssz encode −6%, proposal encode −12%, k1util −7–10%),
**zero effect** on blst-bound (tbls) and synchronization-bound (QBFT) pairs.
Worth adopting for release builds (`[profile.release] lto = "thin",
codegen-units = 1`) as a free single-digit win, but it does not move any of
the structural findings above.

## Where Pluto wins (no action needed)

| pair | ratio | note |
|---|---|---|
| tier1/frost/round1 | 0.19x | 5x faster DKG round 1 |
| tier1/proto/qbft_marshal | 0.39x | prost vs Go protobuf |
| tier1/k1/verify | 0.48–0.54x | |
| tier1/frost/round2 | 0.50x | 2x faster DKG round 2 |
| tier1/tbls/verify_aggregate | 0.60x | blst vs herumi |
| tier1/tbls/verify / sign | 0.67x / 0.72x | blst vs herumi |
| tier3/cli/create_enr | 0.36x | |
| tier3/mem/create_cluster_rss | 0.39x | 14.7 MiB vs 37.6 MiB peak RSS |
| tier3/cli/create_cluster_4 / _10 (insecure) | 0.60x / 0.72x | |
| tier3/dkg/ceremony_4node | 1.00x | 125.7s vs 126.2s over real relay |

## Status update (2026-07-15, after first optimization pass)

Findings 2, 3 (partially), 4 (partially) and the build-config item are
addressed; measured on the same host, non-LTO bench profile:

| pair | before | after | charon | ratio before → after |
|---|---|---|---|---|
| tier1/tbls/threshold_aggregate/3of4 | 407 µs | 205 µs | 300 µs | 1.35x → **0.68x** |
| tier1/tbls/threshold_aggregate/7of10 | 951 µs | 404 µs | 792 µs | 1.20x → **0.51x** |
| tier1/frost/aggregate | 346 µs | 148 µs | 300 µs | 1.15x → **0.49x** |
| tier1/tbls/threshold_split/7of10 | 15.1 µs | 10.0 µs | 5.0 µs | 3.0x → 2.0x |
| tier1/tbls/recover_secret/7of10 | 14.5 µs | 10.1 µs | 4.0 µs | 3.7x → 2.5x |
| tier1/tbls/threshold_split/3of4 | 3.9 µs | 3.3 µs | 1.7 µs | 2.3x → 2.0x |
| tier1/tbls/recover_secret/3of4 | 4.8 µs | 4.1 µs | 1.9 µs | 2.5x → 2.1x |

What changed:

- `blst_impl.rs`: Lagrange signature interpolation now uses blst Pippenger
  multi-scalar multiplication with a single final affine conversion (was one
  scalar mult + one field-inversion-costing affine conversion **per share**);
  polynomial evaluation and secret interpolation moved to fr-domain Horner /
  dot-product arithmetic (fr copies of secret material are volatile-wiped on
  drop). Same treatment for `BlsSignature::from_partial_signatures` in
  `pluto-frost`.
- `ssz_codec.rs`: all encoders pre-size their output buffers
  (`ssz_bytes_len`), versioned encoders append the payload directly after the
  header instead of encoding to a temporary `Vec` and copying, and the
  unsigned Deneb/Electra/Fulu proposal path no longer **deep-clones the block,
  KZG proofs and blobs** to serialize (borrowing `*BlockContentsRef` structs).
  At the small bench fixture sizes this is ~2% on proposal encode and neutral
  on attestation encode — the removed copy/clone scale with real block sizes
  (MB-range with blobs). The residual attestation-encode gap vs fastssz sits
  inside ethereum_ssz's derive machinery (its container encoder allocates an
  internal variable-bytes buffer per call), which would need an upstream
  change or hand-rolled encoders.
- `Cargo.toml`: release profile now sets `lto = "thin"`, `codegen-units = 1`.

Remaining gaps, deliberate for now:

- Shamir split/recover at ~2x: the residue is one checked `SecretKey`
  conversion per share (kept — validates shares exactly like before) and
  coefficient generation via HKDF `key_gen` where herumi draws raw CSPRNG
  scalars. Ceremony-only path; not worth weakening key-generation hygiene.
- QBFT (finding 1) and scrypt/k1-sign (finding 5) untouched, as recommended.

## Recommended order of work

1. **SSZ encode buffer preallocation + header-copy removal** — small, contained
   change in `ssz_codec.rs`, 3–4x on a per-message hot path.
2. **`lagrange_interpolate_signature` cleanup** (skip re-validation, avoid
   affine round-trips, Pippenger) — per-duty win, contained in `blst_impl.rs`.
3. **QBFT instance lifecycle** — replace per-instance thread spawn and 50ms
   cancellation polling; largest ratio but needs a design pass.
4. **Release profile: thin LTO + codegen-units=1** — free ~10% on Rust paths.
5. Ceremony-path items (scrypt, Shamir split, k1 sign) as background work.

## Regenerating

```bash
./perf/run.sh --tier 12     # tiers 1+2 (~20 min)
./perf/run.sh --tier 3      # process level (builds both binaries; DKG needs relay)
```
