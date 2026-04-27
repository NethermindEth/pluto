// Package main generates SSZ-encoded fixture files from Charon's core types.
// These fixtures are used by Pluto's Rust tests to verify byte-for-byte
// interoperability with Go's SSZ encoding.
//
// Usage:
//
//	cd test-infra/sszfixtures && go run . -out ../../crates/core/testdata/ssz
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/core"
)

var outDir = flag.String("out", "../../crates/core/testdata/ssz", "output directory for fixture files")

func main() {
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}

	type fixture struct {
		name string
		gen  func() ([]byte, error)
	}

	fixtures := []fixture{
		{"attestation_phase0", genAttestation},
		{"signed_aggregate_and_proof", genSignedAggregateAndProof},
		{"versioned_attestation_phase0", genVersionedAttestationPhase0},
		{"versioned_agg_proof_phase0", genVersionedSignedAggregatePhase0},
		{"versioned_proposal_phase0", genVersionedProposalPhase0},
	}

	for _, f := range fixtures {
		b, err := f.gen()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR %s: %v\n", f.name, err)
			os.Exit(1)
		}
		path := filepath.Join(*outDir, f.name+".ssz.hex")
		if err := os.WriteFile(path, []byte(hex.EncodeToString(b)), 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("wrote %s (%d bytes)\n", path, len(b))
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
	os.Exit(1)
}

// sampleAttestationData returns deterministic attestation data matching
// Rust test helpers.
func sampleAttestationData() *eth2p0.AttestationData {
	return &eth2p0.AttestationData{
		Slot:            42,
		Index:           7,
		BeaconBlockRoot: fill32(0xaa),
		Source: &eth2p0.Checkpoint{
			Epoch: 10,
			Root:  fill32(0xbb),
		},
		Target: &eth2p0.Checkpoint{
			Epoch: 11,
			Root:  fill32(0xcc),
		},
	}
}

func fill32(b byte) eth2p0.Root {
	var r eth2p0.Root
	for i := range r {
		r[i] = b
	}
	return r
}

func fill96(b byte) eth2p0.BLSSignature {
	var s eth2p0.BLSSignature
	for i := range s {
		s[i] = b
	}
	return s
}

func fillHash32(b byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = b
	}
	return h
}

// bitlistN creates an SSZ-encoded bitlist with the given capacity and set bits.
func bitlistN(capacity int, setBits ...int) []byte {
	byteLen := (capacity + 7) / 8
	b := make([]byte, byteLen+1)
	for _, bit := range setBits {
		b[bit/8] |= 1 << uint(bit%8)
	}
	// Append sentinel bit.
	sentinelByte := capacity / 8
	sentinelBit := capacity % 8
	if sentinelByte < len(b) {
		b[sentinelByte] |= 1 << uint(sentinelBit)
	}
	// Trim trailing zero bytes after sentinel.
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

func genAttestation() ([]byte, error) {
	att := core.NewAttestation(&eth2p0.Attestation{
		AggregationBits: bitlistN(16, 0, 3, 7),
		Data:            sampleAttestationData(),
		Signature:       fill96(0x11),
	})
	return att.MarshalSSZ()
}

func genSignedAggregateAndProof() ([]byte, error) {
	sap := core.NewSignedAggregateAndProof(&eth2p0.SignedAggregateAndProof{
		Message: &eth2p0.AggregateAndProof{
			AggregatorIndex: 99,
			Aggregate: &eth2p0.Attestation{
				AggregationBits: bitlistN(8, 2, 4),
				Data:            sampleAttestationData(),
				Signature:       fill96(0x33),
			},
			SelectionProof: fill96(0x44),
		},
		Signature: fill96(0x55),
	})
	return sap.MarshalSSZ()
}

func genVersionedAttestationPhase0() ([]byte, error) {
	va, err := core.NewVersionedAttestation(&spec.VersionedAttestation{
		Version: spec.DataVersionPhase0,
		Phase0: &eth2p0.Attestation{
			AggregationBits: bitlistN(8, 1, 3),
			Data:            sampleAttestationData(),
			Signature:       fill96(0x11),
		},
	})
	if err != nil {
		return nil, err
	}
	return va.MarshalSSZ()
}

func genVersionedSignedAggregatePhase0() ([]byte, error) {
	va := core.NewVersionedSignedAggregateAndProof(&spec.VersionedSignedAggregateAndProof{
		Version: spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedAggregateAndProof{
			Message: &eth2p0.AggregateAndProof{
				AggregatorIndex: 55,
				Aggregate: &eth2p0.Attestation{
					AggregationBits: bitlistN(4, 0),
					Data:            sampleAttestationData(),
					Signature:       fill96(0xaa),
				},
				SelectionProof: fill96(0xbb),
			},
			Signature: fill96(0xcc),
		},
	})
	return va.MarshalSSZ()
}

func genVersionedProposalPhase0() ([]byte, error) {
	vp, err := core.NewVersionedSignedProposal(&api.VersionedSignedProposal{
		Version: spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedBeaconBlock{
			Message: &eth2p0.BeaconBlock{
				Slot:          1,
				ProposerIndex: 2,
				ParentRoot:    fill32(0x11),
				StateRoot:     fill32(0x22),
				Body: &eth2p0.BeaconBlockBody{
					RANDAOReveal: fill96(0x33),
					ETH1Data: &eth2p0.ETH1Data{
						DepositRoot:  fill32(0x44),
						DepositCount: 0,
						BlockHash:    fillHash32(0x55),
					},
					Graffiti: fill32(0x66),
				},
			},
			Signature: fill96(0x77),
		},
	})
	if err != nil {
		return nil, err
	}
	return vp.MarshalSSZ()
}
