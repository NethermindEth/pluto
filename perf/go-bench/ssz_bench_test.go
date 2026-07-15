package perfbench

import (
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/core"
)

func BenchmarkTier1SszAttEncode(b *testing.B) {
	data := loadFixture(b, "phase0_attestation.ssz")

	att := new(eth2p0.Attestation)
	if err := att.UnmarshalSSZ(data); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := att.MarshalSSZ(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTier1SszAttDecode(b *testing.B) {
	data := loadFixture(b, "phase0_attestation.ssz")

	b.ReportAllocs()

	for b.Loop() {
		att := new(eth2p0.Attestation)
		if err := att.UnmarshalSSZ(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTier1SszAttHashRoot(b *testing.B) {
	data := loadFixture(b, "phase0_attestation.ssz")

	att := new(eth2p0.Attestation)
	if err := att.UnmarshalSSZ(data); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := att.HashTreeRoot(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTier1SszProposalEncode(b *testing.B) {
	data := loadFixture(b, "deneb_signed_proposal.ssz")

	proposal := new(core.VersionedSignedProposal)
	if err := proposal.UnmarshalSSZ(data); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := proposal.MarshalSSZ(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTier1SszProposalDecode(b *testing.B) {
	data := loadFixture(b, "deneb_signed_proposal.ssz")

	b.ReportAllocs()

	for b.Loop() {
		proposal := new(core.VersionedSignedProposal)
		if err := proposal.UnmarshalSSZ(data); err != nil {
			b.Fatal(err)
		}
	}
}
