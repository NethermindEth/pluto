//! # k1util benchmarks
//!
//! Benchmarks for the k1util module.
#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use k256::{SecretKey, elliptic_curve::rand_core::OsRng};

// Assuming your crate is named "charon" - adjust if different
use charon::k1util::{K1_HASH_LEN, SIGNATURE_LEN, recover, sign, verify_64};

fn setup() -> (SecretKey, Vec<u8>, Vec<u8>) {
    let key = SecretKey::random(&mut OsRng);
    let digest = vec![0u8; K1_HASH_LEN];
    let sig = sign(&key, &digest).expect("sign should succeed");

    (key, digest, sig.to_vec())
}

fn bench_sign(c: &mut Criterion) {
    let key = SecretKey::random(&mut OsRng);
    let digest = vec![0u8; K1_HASH_LEN];

    c.bench_function("sign", |b| {
        b.iter(|| sign(black_box(&key), black_box(&digest)).expect("sign should succeed"))
    });
}

fn bench_recover(c: &mut Criterion) {
    let (key, digest, sig) = setup();
    let pubkey = key.public_key();

    c.bench_function("recover", |b| {
        b.iter(|| {
            let recovered =
                recover(black_box(&digest), black_box(&sig)).expect("recover should succeed");
            assert_eq!(recovered, pubkey);
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let (key, digest, sig) = setup();
    let pubkey = key.public_key();

    c.bench_function("verify", |b| {
        b.iter(|| {
            let ok = verify_64(
                black_box(&pubkey),
                black_box(&digest),
                black_box(&sig[..SIGNATURE_LEN - 1]),
            )
            .expect("verify should succeed");
            assert!(ok);
        })
    });
}

criterion_group!(benches, bench_sign, bench_recover, bench_verify);
criterion_main!(benches);
