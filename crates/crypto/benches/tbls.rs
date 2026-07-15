//! Benchmarks for the BLS threshold-signature implementation.
//!
//! Benchmark ids follow the cross-language pair naming used by
//! `perf/pairs.json`; the Go counterparts live in `perf/go-bench/`.
#![allow(missing_docs)]

use std::{collections::HashMap, hint::black_box, time::Duration};

use criterion::{Criterion, criterion_group, criterion_main};
use pluto_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    types::{Index, PrivateKey, PublicKey, Signature},
};
use rand::rngs::OsRng;

/// Must stay identical to the message in `perf/go-bench/tbls_bench_test.go`
/// so both sides time the same workload.
const MSG: [u8; 32] = [0u8; 32];

const SPLIT_CASES: [(&str, Index, Index); 2] = [("3of4", 4, 3), ("7of10", 10, 7)];

fn new_secret() -> PrivateKey {
    BlstImpl
        .generate_secret_key(OsRng)
        .expect("bench setup: keygen")
}

/// Returns `threshold` partial signatures over [`MSG`] from a fresh
/// threshold-split key, keyed by 1-indexed share ID.
fn partial_signatures(total: Index, threshold: Index) -> HashMap<Index, Signature> {
    let tbls = BlstImpl;
    let shares = tbls
        .threshold_split(&new_secret(), total, threshold)
        .expect("bench setup: split");

    (1..=threshold)
        .map(|idx| {
            let share = shares.get(&idx).expect("bench setup: share");
            let sig = tbls.sign(share, &MSG).expect("bench setup: sign");
            (idx, sig)
        })
        .collect()
}

fn bench_sign(c: &mut Criterion) {
    let tbls = BlstImpl;
    let secret = new_secret();

    c.bench_function("tier1/tbls/sign", |b| {
        b.iter(|| {
            tbls.sign(black_box(&secret), black_box(&MSG))
                .expect("sign should succeed")
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let tbls = BlstImpl;
    let secret = new_secret();
    let pubkey = tbls
        .secret_to_public_key(&secret)
        .expect("bench setup: pubkey");
    let sig = tbls.sign(&secret, &MSG).expect("bench setup: sign");

    c.bench_function("tier1/tbls/verify", |b| {
        b.iter(|| {
            tbls.verify(black_box(&pubkey), black_box(&MSG), black_box(&sig))
                .expect("verify should succeed")
        })
    });
}

fn bench_verify_aggregate(c: &mut Criterion) {
    const KEYS: usize = 4;

    let tbls = BlstImpl;
    let mut pubkeys: Vec<PublicKey> = Vec::with_capacity(KEYS);
    let mut sigs: Vec<Signature> = Vec::with_capacity(KEYS);

    for _ in 0..KEYS {
        let secret = new_secret();
        pubkeys.push(
            tbls.secret_to_public_key(&secret)
                .expect("bench setup: pubkey"),
        );
        sigs.push(tbls.sign(&secret, &MSG).expect("bench setup: sign"));
    }

    let agg_sig = tbls.aggregate(&sigs).expect("bench setup: aggregate");

    c.bench_function("tier1/tbls/verify_aggregate", |b| {
        b.iter(|| {
            tbls.verify_aggregate(black_box(&pubkeys), black_box(agg_sig), black_box(&MSG))
                .expect("verify_aggregate should succeed")
        })
    });
}

fn bench_threshold_split(c: &mut Criterion) {
    let tbls = BlstImpl;
    let secret = new_secret();

    for (name, total, threshold) in SPLIT_CASES {
        c.bench_function(&format!("tier1/tbls/threshold_split/{name}"), |b| {
            b.iter(|| {
                tbls.threshold_split(black_box(&secret), black_box(total), black_box(threshold))
                    .expect("threshold_split should succeed")
            })
        });
    }
}

fn bench_threshold_aggregate(c: &mut Criterion) {
    let tbls = BlstImpl;

    for (name, total, threshold) in SPLIT_CASES {
        let partial_sigs = partial_signatures(total, threshold);

        c.bench_function(&format!("tier1/tbls/threshold_aggregate/{name}"), |b| {
            b.iter(|| {
                tbls.threshold_aggregate(black_box(&partial_sigs))
                    .expect("threshold_aggregate should succeed")
            })
        });
    }
}

fn bench_recover_secret(c: &mut Criterion) {
    let tbls = BlstImpl;

    for (name, total, threshold) in SPLIT_CASES {
        let shares = tbls
            .threshold_split(&new_secret(), total, threshold)
            .expect("bench setup: split");
        let subset: HashMap<Index, PrivateKey> = (1..=threshold)
            .map(|idx| (idx, *shares.get(&idx).expect("bench setup: share")))
            .collect();

        c.bench_function(&format!("tier1/tbls/recover_secret/{name}"), |b| {
            b.iter(|| {
                tbls.recover_secret(black_box(&subset))
                    .expect("recover_secret should succeed")
            })
        });
    }
}

fn config() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .measurement_time(Duration::from_secs(3))
}

criterion_group! {
    name = benches;
    config = config();
    targets = bench_sign,
        bench_verify,
        bench_verify_aggregate,
        bench_threshold_split,
        bench_threshold_aggregate,
        bench_recover_secret,
}
criterion_main!(benches);
