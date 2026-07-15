// Package perfbench benchmarks charon's hot paths with workloads that mirror
// the Pluto criterion benches one-to-one. Pair mapping lives in perf/pairs.json.
package perfbench

import (
	"testing"

	"github.com/obolnetwork/charon/tbls"
)

// msg32 mirrors the 32-byte all-zero message used by the Rust benches.
var msg32 = make([]byte, 32)

type splitCase struct {
	name      string
	total     uint
	threshold uint
}

var splitCases = []splitCase{
	{name: "3of4", total: 4, threshold: 3},
	{name: "7of10", total: 10, threshold: 7},
}

func BenchmarkTier1TblsSign(b *testing.B) {
	secret, err := tbls.GenerateSecretKey()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := tbls.Sign(secret, msg32); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTier1TblsVerify(b *testing.B) {
	secret, err := tbls.GenerateSecretKey()
	if err != nil {
		b.Fatal(err)
	}

	pubkey, err := tbls.SecretToPublicKey(secret)
	if err != nil {
		b.Fatal(err)
	}

	sig, err := tbls.Sign(secret, msg32)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if err := tbls.Verify(pubkey, msg32, sig); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTier1TblsVerifyAggregate(b *testing.B) {
	const keys = 4

	var (
		pubkeys []tbls.PublicKey
		sigs    []tbls.Signature
	)

	for range keys {
		secret, err := tbls.GenerateSecretKey()
		if err != nil {
			b.Fatal(err)
		}

		pubkey, err := tbls.SecretToPublicKey(secret)
		if err != nil {
			b.Fatal(err)
		}

		sig, err := tbls.Sign(secret, msg32)
		if err != nil {
			b.Fatal(err)
		}

		pubkeys = append(pubkeys, pubkey)
		sigs = append(sigs, sig)
	}

	aggSig, err := tbls.Aggregate(sigs)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if err := tbls.VerifyAggregate(pubkeys, aggSig, msg32); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTier1TblsThresholdSplit(b *testing.B) {
	secret, err := tbls.GenerateSecretKey()
	if err != nil {
		b.Fatal(err)
	}

	for _, tc := range splitCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				if _, err := tbls.ThresholdSplit(secret, tc.total, tc.threshold); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTier1TblsThresholdAggregate(b *testing.B) {
	for _, tc := range splitCases {
		b.Run(tc.name, func(b *testing.B) {
			partialSigs := partialSignatures(b, tc)

			b.ReportAllocs()

			for b.Loop() {
				if _, err := tbls.ThresholdAggregate(partialSigs); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTier1TblsRecoverSecret(b *testing.B) {
	for _, tc := range splitCases {
		b.Run(tc.name, func(b *testing.B) {
			secret, err := tbls.GenerateSecretKey()
			if err != nil {
				b.Fatal(err)
			}

			shares, err := tbls.ThresholdSplit(secret, tc.total, tc.threshold)
			if err != nil {
				b.Fatal(err)
			}

			subset := make(map[int]tbls.PrivateKey)
			for idx := 1; idx <= int(tc.threshold); idx++ {
				subset[idx] = shares[idx]
			}

			b.ReportAllocs()

			for b.Loop() {
				if _, err := tbls.RecoverSecret(subset, tc.total, tc.threshold); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// partialSignatures returns threshold partial signatures over msg32 from a
// fresh threshold-split key, keyed by 1-indexed share ID.
func partialSignatures(b *testing.B, tc splitCase) map[int]tbls.Signature {
	b.Helper()

	secret, err := tbls.GenerateSecretKey()
	if err != nil {
		b.Fatal(err)
	}

	shares, err := tbls.ThresholdSplit(secret, tc.total, tc.threshold)
	if err != nil {
		b.Fatal(err)
	}

	partialSigs := make(map[int]tbls.Signature)

	for idx := 1; idx <= int(tc.threshold); idx++ {
		sig, err := tbls.Sign(shares[idx], msg32)
		if err != nil {
			b.Fatal(err)
		}

		partialSigs[idx] = sig
	}

	return partialSigs
}
