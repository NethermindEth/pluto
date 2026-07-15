package perfbench

import (
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
)

// Mirrors the 3-of-4 single-validator workload of the Rust frost benches.
const (
	frostThreshold = uint32(3)
	frostTotal     = uint32(4)
	frostCtx       = "0"
)

var frostCurve = curves.BLS12381G1()

func newFrostParticipant(tb testing.TB, id uint32) *frost.DkgParticipant {
	tb.Helper()

	var otherIDs []uint32

	for i := uint32(1); i <= frostTotal; i++ {
		if i != id {
			otherIDs = append(otherIDs, i)
		}
	}

	participant, err := frost.NewDkgParticipant(id, frostThreshold, frostCtx, frostCurve, otherIDs...)
	if err != nil {
		tb.Fatal(err)
	}

	return participant
}

// round2Inputs runs round 1 for every participant and returns participant 1
// with its round-2 inputs: all broadcasts (own included, matching charon's
// getRound2Inputs) plus the Shamir shares addressed to participant 1.
func round2Inputs(tb testing.TB) (*frost.DkgParticipant, map[uint32]*frost.Round1Bcast, map[uint32]*sharing.ShamirShare) {
	tb.Helper()

	bcasts := make(map[uint32]*frost.Round1Bcast)
	sharesToOne := make(map[uint32]*sharing.ShamirShare)

	var participantOne *frost.DkgParticipant

	for id := uint32(1); id <= frostTotal; id++ {
		participant := newFrostParticipant(tb, id)

		bcast, p2p, err := participant.Round1(nil)
		if err != nil {
			tb.Fatal(err)
		}

		bcasts[id] = bcast

		if id == 1 {
			participantOne = participant
		} else {
			sharesToOne[id] = p2p[1]
		}
	}

	return participantOne, bcasts, sharesToOne
}

func BenchmarkTier1FrostRound1(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		participant := newFrostParticipant(b, 1)
		if _, _, err := participant.Round1(nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTier1FrostRound2(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		b.StopTimer()
		participant, bcasts, shares := round2Inputs(b)
		b.StartTimer()

		if _, err := participant.Round2(bcasts, shares); err != nil {
			b.Fatal(err)
		}
	}
}
