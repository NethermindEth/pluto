package harness

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

// SimResult is one signed-data set a node handed to its broadcaster,
// mirroring charon's upstream simnet result tuple.
type SimResult struct {
	PeerIdx int
	Duty    core.Duty
	Pubkey  core.PubKey
	Data    core.SignedData
}

// CharonMode selects how an in-process charon node reaches its beacon node.
type CharonMode int

const (
	// CharonInProcessBMock uses charon's built-in simnet beaconmock, as
	// upstream simnet does. Fastest and independent of the gateway.
	CharonInProcessBMock CharonMode = iota
	// CharonViaGateway connects to a harness beacon gateway over real HTTP,
	// exercising the exact beacon-node surface subprocess nodes use.
	CharonViaGateway
)

// StartCharonNode runs one in-process charon node on the errgroup. It
// mirrors charon's upstream simnet config with one deliberate difference:
// no in-memory ParSigExFunc, so partial-signature exchange runs over real
// p2p and out-of-process nodes can participate.
func StartCharonNode(
	t *testing.T,
	ctx context.Context,
	eg *errgroup.Group,
	cancel context.CancelFunc,
	fixture *Fixture,
	peerIdx int,
	relayAddr string,
	mode CharonMode,
	gatewayAddr string,
	results chan<- SimResult,
) {
	t.Helper()

	conf := app.Config{
		Log:              log.DefaultConfig(),
		Feature:          featureset.DefaultConfig(),
		SimnetBMock:      mode == CharonInProcessBMock,
		SimnetVMock:      true,
		MonitoringAddr:   testutil.AvailableAddr(t).String(),
		ValidatorAPIAddr: fixture.VAPIAddrs[peerIdx],
		TestConfig: app.TestConfig{
			Lock:   &fixture.Lock,
			P2PKey: fixture.P2PKeys[peerIdx],
			TestPingConfig: p2p.TestPingConfig{
				MaxBackoff: time.Second,
			},
			SimnetKeys: fixture.NodeSecrets(peerIdx),
			BroadcastCallback: func(_ context.Context, duty core.Duty, set core.SignedDataSet) error {
				for key, data := range set {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case results <- SimResult{Duty: duty, Pubkey: key, Data: data, PeerIdx: peerIdx}:
					}
				}

				return nil
			},
		},
		P2P: p2p.Config{
			TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			Relays:   []string{relayAddr},
		},
	}

	switch mode {
	case CharonInProcessBMock:
		conf.TestConfig.SimnetBMockOpts = simnetBMockOpts()
	case CharonViaGateway:
		conf.BeaconNodeAddrs = []string{gatewayAddr}
		// Defaults from `charon run` flags, required by the non-simnet
		// eth2 client path.
		conf.BeaconNodeTimeout = 2 * time.Second
		conf.BeaconNodeSubmitTimeout = 2 * time.Second
	}

	eg.Go(func() error {
		defer cancel()
		return app.Run(ctx, conf)
	})
}
