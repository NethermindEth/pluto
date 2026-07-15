package perfbench

import (
	"testing"

	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"google.golang.org/protobuf/proto"
)

func BenchmarkTier1ProtoQbftMarshal(b *testing.B) {
	data := loadFixture(b, "qbft_consensus_msg.pb")

	msg := new(pbv1.QBFTConsensusMsg)
	if err := proto.Unmarshal(data, msg); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := proto.Marshal(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTier1ProtoQbftUnmarshal(b *testing.B) {
	data := loadFixture(b, "qbft_consensus_msg.pb")

	b.ReportAllocs()

	for b.Loop() {
		msg := new(pbv1.QBFTConsensusMsg)
		if err := proto.Unmarshal(data, msg); err != nil {
			b.Fatal(err)
		}
	}
}
