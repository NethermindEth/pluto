//! Benchmarks a full in-process FROST DKG ceremony over the in-memory
//! transport (no networking).
//!
//! Rust-only informational benchmark: charon has no in-memory DKG transport,
//! so the cross-implementation comparison happens at process level (tier 3).
//! Requires the `bench-util` feature:
//! `cargo bench -p pluto-dkg --features bench-util`.
#![allow(missing_docs)]

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use pluto_dkg::frost_bench_util::run_mem_dkg;

const NODES: u32 = 4;
const THRESHOLD: u32 = 3;

fn bench_mem_ceremony(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("bench setup: tokio runtime");

    for vals in [1u32, 10] {
        c.bench_function(&format!("tier2/dkg/mem_ceremony/{vals}vals"), |b| {
            b.iter(|| runtime.block_on(run_mem_dkg(NODES, THRESHOLD, vals)))
        });
    }
}

fn config() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(5))
}

criterion_group! {
    name = benches;
    config = config();
    targets = bench_mem_ceremony,
}
criterion_main!(benches);
