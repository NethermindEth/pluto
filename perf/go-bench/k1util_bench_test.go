package perfbench

import (
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/obolnetwork/charon/app/k1util"
)

// digest32 mirrors the 32-byte all-zero digest used by the Rust k1util bench.
var digest32 = make([]byte, 32)

func BenchmarkTier1K1Sign(b *testing.B) {
	key, err := k1.GeneratePrivateKey()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := k1util.Sign(key, digest32); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTier1K1Recover(b *testing.B) {
	key, err := k1.GeneratePrivateKey()
	if err != nil {
		b.Fatal(err)
	}

	sig, err := k1util.Sign(key, digest32)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		recovered, err := k1util.Recover(digest32, sig)
		if err != nil {
			b.Fatal(err)
		}

		if !recovered.IsEqual(key.PubKey()) {
			b.Fatal("recovered wrong public key")
		}
	}
}

func BenchmarkTier1K1Verify(b *testing.B) {
	key, err := k1.GeneratePrivateKey()
	if err != nil {
		b.Fatal(err)
	}

	sig, err := k1util.Sign(key, digest32)
	if err != nil {
		b.Fatal(err)
	}

	pubkey := key.PubKey()

	b.ReportAllocs()

	for b.Loop() {
		ok, err := k1util.Verify64(pubkey, digest32, sig[:64])
		if err != nil {
			b.Fatal(err)
		}

		if !ok {
			b.Fatal("signature did not verify")
		}
	}
}
