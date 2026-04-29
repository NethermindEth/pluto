# Kryptology-Compatible Distributed Key Generation (DKG)

The kryptology DKG module supports generating FROST key shares in a distributed
manner compatible with Go's Coinbase Kryptology FROST DKG.

The output types ([`KeyPackage`], [`PublicKeyPackage`]) are standard frost-core
types. The key shares can be used for BLS threshold signing via the
`bls_partial_sign`, `bls_combine_signatures`, and `bls_verify` functions.

## Wire contract

The supported cross-language contract is the raw field encoding used by the
fixtures and round helpers in this module:

- Scalars are 32-byte big-endian field elements.
- G1 points are 48-byte compressed encodings.
- Participant identifiers are transported as `u32` values.
- The DKG context is transported as a single `u8` byte.

Gob encoding is not part of this interoperability contract.

## Example

```rust
use std::collections::BTreeMap;

use pluto_frost::kryptology;

let mut rng = rand::rngs::OsRng;

let threshold = 3u16;
let max_signers = 5u16;
let ctx = 0u8;

// Round 1: each participant generates broadcast data and shares.
let mut bcasts: BTreeMap<u32, kryptology::Round1Bcast> = BTreeMap::new();
let mut all_shares: BTreeMap<u32, BTreeMap<u32, kryptology::ShamirShare>> = BTreeMap::new();
let mut secrets: BTreeMap<u32, kryptology::Round1Secret> = BTreeMap::new();

for id in 1..=max_signers as u32 {
    let (bcast, shares, secret) =
        kryptology::round1(id, threshold, max_signers, ctx, &mut rng)
            .expect("round1 should succeed");
    bcasts.insert(id, bcast);
    secrets.insert(id, secret);
    for (&target_id, share) in &shares {
        all_shares.entry(target_id).or_default().insert(id, share.clone());
    }
}

// Round 2: each participant verifies broadcasts and aggregates shares.
let mut key_packages = BTreeMap::new();
let mut public_key_packages = Vec::new();

for id in 1..=max_signers as u32 {
    let received_bcasts: BTreeMap<_, _> = bcasts
        .iter()
        .filter(|(k, _)| **k != id)
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let received_shares = all_shares.remove(&id).unwrap();
    let secret = secrets.remove(&id).unwrap();

    let (_r2_bcast, key_package, pub_package) =
        kryptology::round2(secret, &received_bcasts, &received_shares)
            .expect("round2 should succeed");
    key_packages.insert(id, key_package);
    public_key_packages.push(pub_package);
}

// Each participant now has a KeyPackage and PublicKeyPackage for BLS threshold signing.
```
