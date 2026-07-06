package harness

import (
	"context"
	"sync"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

// Submission is a request an external node POSTed to its beacon gateway.
type Submission struct {
	NodeIdx          int
	Path             string
	ConsensusVersion string
	Body             []byte
	At               time.Time
}

// BeaconNet is a single shared beaconmock fronted by one HTTP gateway per
// node. All gateways serve the same mock state, so every node observes the
// same chain and duties, while submissions remain attributable per node.
type BeaconNet struct {
	Mock         beaconmock.Mock
	GatewayAddrs []string // http://127.0.0.1:port per node

	mu   sync.Mutex
	subs []Submission
}

// StartBeaconNet starts the shared beaconmock and one gateway per node.
// The mock options mirror charon's app simnet wiring (app.newETH2Client)
// plus the upstream simnet test overrides for an attester-only flow.
func StartBeaconNet(t *testing.T, ctx context.Context, fixture *Fixture, opts ...beaconmock.Option) *BeaconNet {
	t.Helper()

	genesisTime, err := eth2util.ForkVersionToGenesisTime(simnetForkVersion)
	require.NoError(t, err)

	mockOpts := append(simnetBMockOpts(),
		beaconmock.WithSlotDuration(time.Second),
		beaconmock.WithGenesisTime(genesisTime),
		beaconmock.WithDeterministicAttesterDuties(dutyFactor),
		beaconmock.WithValidatorSet(mockValidators(fixture.DVPubkeys(t))),
	)
	mockOpts = append(mockOpts, opts...)

	mock, err := beaconmock.New(ctx, mockOpts...)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = mock.Close()
	})

	net := &BeaconNet{Mock: mock}

	for i := range fixture.N {
		addr := startGateway(t, net, i)
		net.GatewayAddrs = append(net.GatewayAddrs, addr)
	}

	return net
}

// dutyFactor spreads duties deterministically in an epoch, mirroring
// charon's app simnet wiring.
const dutyFactor = 100

// simnetBMockOpts returns the beaconmock options charon's upstream simnet
// test layers on top of the app defaults: single-slot epochs and an
// attester-only duty flow.
func simnetBMockOpts() []beaconmock.Option {
	return []beaconmock.Option{
		beaconmock.WithSlotsPerEpoch(1),
		beaconmock.WithNoProposerDuties(),
		beaconmock.WithNoSyncCommitteeDuties(),
	}
}

// record stores a submission for later assertion.
func (n *BeaconNet) record(sub Submission) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.subs = append(n.subs, sub)
}

// Submissions returns a snapshot of all captured submissions.
func (n *BeaconNet) Submissions() []Submission {
	n.mu.Lock()
	defer n.mu.Unlock()

	return append([]Submission(nil), n.subs...)
}

// mockValidators mirrors charon's unexported app.createMockValidators: it
// registers the cluster's distributed validators as active validators in
// the beaconmock.
func mockValidators(pubkeys []eth2p0.BLSPubKey) beaconmock.ValidatorSet {
	resp := make(beaconmock.ValidatorSet)

	for i, pubkey := range pubkeys {
		vIdx := eth2p0.ValidatorIndex(i)

		resp[vIdx] = &eth2v1.Validator{
			Balance: eth2p0.Gwei(31300000000),
			Index:   vIdx,
			Status:  eth2v1.ValidatorStateActiveOngoing,
			Validator: &eth2p0.Validator{
				WithdrawalCredentials: []byte("12345678901234567890123456789012"),
				EffectiveBalance:      eth2p0.Gwei(31300000000),
				PublicKey:             pubkey,
				ExitEpoch:             18446744073709551615,
				WithdrawableEpoch:     18446744073709551615,
			},
		}
	}

	return resp
}
