package perfbench

import (
	"os"
	"path/filepath"
	"testing"

	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/testutil"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// TestGenFixtures regenerates the shared binary fixtures in perf/fixtures/
// consumed by both the Go and Rust benches. It is guarded by WRITE_FIXTURES=1
// so bench runs (-run '^$') and normal test runs skip it:
//
//	WRITE_FIXTURES=1 go test -run TestGenFixtures .
func TestGenFixtures(t *testing.T) {
	if os.Getenv("WRITE_FIXTURES") != "1" {
		t.Skip("set WRITE_FIXTURES=1 to regenerate fixtures")
	}

	att := testutil.RandomPhase0Attestation()

	attBytes, err := att.MarshalSSZ()
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, "phase0_attestation.ssz", attBytes)

	proposal := testutil.RandomDenebCoreVersionedSignedProposal()

	proposalBytes, err := proposal.MarshalSSZ()
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, "deneb_signed_proposal.ssz", proposalBytes)

	msgBytes, err := proto.Marshal(qbftConsensusMsgFixture())
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, "qbft_consensus_msg.pb", msgBytes)
}

func writeFixture(t *testing.T, name string, data []byte) {
	t.Helper()

	path := filepath.Join("..", "fixtures", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Logf("wrote %s (%d bytes)", path, len(data))
}

func loadFixture(tb testing.TB, name string) []byte {
	tb.Helper()

	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	if err != nil {
		tb.Fatalf("read fixture (regenerate with WRITE_FIXTURES=1 go test -run TestGenFixtures .): %v", err)
	}

	return data
}

// qbftConsensusMsgFixture builds a deterministic QBFTConsensusMsg shaped like
// a round-3 PRE_PREPARE with a round-change justification from every peer.
func qbftConsensusMsgFixture() *pbv1.QBFTConsensusMsg {
	justification := make([]*pbv1.QBFTMsg, 0, 4)
	for peer := int64(0); peer < 4; peer++ {
		justification = append(justification, qbftMsgFixture(peer, 3))
	}

	return &pbv1.QBFTConsensusMsg{
		Msg:           qbftMsgFixture(1, 3),
		Justification: justification,
		Values: []*anypb.Any{
			{
				TypeUrl: "charon/perf-fixture-value",
				Value:   patternBytes(1024, 0xCD),
			},
		},
	}
}

func qbftMsgFixture(peerIdx, round int64) *pbv1.QBFTMsg {
	return &pbv1.QBFTMsg{
		Type:              1,
		Duty:              &pbv1.Duty{Slot: 12345678, Type: 1},
		PeerIdx:           peerIdx,
		Round:             round,
		PreparedRound:     round - 1,
		Signature:         patternBytes(96, byte(peerIdx)),
		ValueHash:         patternBytes(32, 0xAA),
		PreparedValueHash: patternBytes(32, 0xBB),
	}
}

func patternBytes(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i%7)
	}

	return out
}
