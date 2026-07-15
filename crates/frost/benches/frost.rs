//! Benchmarks for the kryptology-compatible FROST DKG rounds and BLS
//! partial-signature operations.
//!
//! Benchmark ids follow the cross-language pair naming used by
//! `perf/pairs.json`; the Go counterparts live in `perf/go-bench/`.
#![allow(missing_docs)]

use std::{collections::BTreeMap, time::Duration};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use pluto_frost::{
    KeyPackage,
    kryptology::{
        BlsPartialSignature, BlsSignature, Round1Bcast, Round1Secret, ShamirShare, round1, round2,
    },
};
use rand::rngs::OsRng;

/// Must stay identical to the workload in
/// `perf/go-bench/frost_bench_test.go` so both sides time the same thing.
const THRESHOLD: u16 = 3;
const TOTAL: u16 = 4;
const CTX: u8 = 0;

/// Must stay identical to the message in `perf/go-bench/frost_bench_test.go`.
const MSG: [u8; 32] = [0u8; 32];

struct Round2Input {
    secret: Round1Secret,
    bcasts: BTreeMap<u32, Round1Bcast>,
    shares: BTreeMap<u32, ShamirShare>,
}

/// Runs round 1 for every participant and returns participant 1's round-2
/// inputs: all broadcasts (a node's own round-1 broadcast is included, as in
/// a real ceremony) plus the Shamir shares addressed to participant 1.
fn round2_input() -> Round2Input {
    let mut rng = OsRng;
    let mut bcasts = BTreeMap::new();
    let mut shares_to_one = BTreeMap::new();
    let mut secret_one = None;

    for id in 1..=u32::from(TOTAL) {
        let (bcast, mut shares, secret) =
            round1(id, THRESHOLD, TOTAL, CTX, &mut rng).expect("bench setup: round1");

        bcasts.insert(id, bcast);

        if id == 1 {
            secret_one = Some(secret);
        } else {
            let share = shares.remove(&1).expect("bench setup: share for 1");
            shares_to_one.insert(id, share);
        }
    }

    Round2Input {
        secret: secret_one.expect("bench setup: participant 1 secret"),
        bcasts,
        shares: shares_to_one,
    }
}

/// Runs a full in-process 3-of-4 DKG and returns every participant's
/// [`KeyPackage`].
fn key_packages() -> Vec<KeyPackage> {
    let mut rng = OsRng;
    let mut bcasts = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    let mut shares_by_target: BTreeMap<u32, BTreeMap<u32, ShamirShare>> = BTreeMap::new();

    for id in 1..=u32::from(TOTAL) {
        let (bcast, shares, secret) =
            round1(id, THRESHOLD, TOTAL, CTX, &mut rng).expect("bench setup: round1");

        bcasts.insert(id, bcast);
        secrets.insert(id, secret);

        for (target, share) in shares {
            shares_by_target
                .entry(target)
                .or_default()
                .insert(id, share);
        }
    }

    secrets
        .into_iter()
        .map(|(id, secret)| {
            let shares = shares_by_target
                .remove(&id)
                .expect("bench setup: shares for participant");
            let (_, key_package, _) =
                round2(secret, &bcasts, &shares).expect("bench setup: round2");
            key_package
        })
        .collect()
}

fn bench_round1(c: &mut Criterion) {
    c.bench_function("tier1/frost/round1", |b| {
        let mut rng = OsRng;
        b.iter(|| round1(1, THRESHOLD, TOTAL, CTX, &mut rng).expect("round1 should succeed"))
    });
}

fn bench_round2(c: &mut Criterion) {
    c.bench_function("tier1/frost/round2", |b| {
        b.iter_batched(
            round2_input,
            |input| {
                round2(input.secret, &input.bcasts, &input.shares).expect("round2 should succeed")
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_partial_sign(c: &mut Criterion) {
    let key_package = key_packages().into_iter().next().expect("bench setup");

    c.bench_function("tier1/frost/partial_sign", |b| {
        b.iter(|| BlsPartialSignature::from_key_package(&key_package, &MSG))
    });
}

fn bench_aggregate(c: &mut Criterion) {
    let partials: Vec<BlsPartialSignature> = key_packages()
        .iter()
        .take(usize::from(THRESHOLD))
        .map(|kp| BlsPartialSignature::from_key_package(kp, &MSG))
        .collect();

    c.bench_function("tier1/frost/aggregate", |b| {
        b.iter(|| {
            BlsSignature::from_partial_signatures(THRESHOLD, &partials)
                .expect("aggregate should succeed")
        })
    });
}

fn config() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .measurement_time(Duration::from_secs(3))
}

criterion_group! {
    name = benches;
    config = config();
    targets = bench_round1, bench_round2, bench_partial_sign, bench_aggregate,
}
criterion_main!(benches);
