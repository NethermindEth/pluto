package harness

import (
	"context"
	"sync"
	"testing"
	"time"

	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil/validatormock"
)

// StartValidatorMock starts a validator mock for node i, connecting to its
// validator API over HTTP. This mirrors charon's app/vmock.go wiring, except
// the slot ticker is harness-owned (the node is out of process, so we cannot
// subscribe to its scheduler).
func StartValidatorMock(t *testing.T, ctx context.Context, fixture *Fixture, peerIdx int) {
	t.Helper()

	signer, err := validatormock.NewSigner(fixture.NodeSecrets(peerIdx)...)
	require.NoError(t, err)

	pubshares := fixture.NodePubshares(t, peerIdx)
	provider := cachedEth2Provider("http://"+fixture.VAPIAddrs[peerIdx], pubshares)

	// Fetch chain metadata through the node's validator API (it proxies to
	// the beacon node), retrying while the node starts up.
	var (
		genesisTime   time.Time
		slotDuration  time.Duration
		slotsPerEpoch uint64
	)

	require.Eventually(t, func() bool {
		eth2Cl, err := provider()
		if err != nil {
			return false
		}

		genesisTime, err = eth2wrap.FetchGenesisTime(ctx, eth2Cl)
		if err != nil {
			return false
		}

		slotDuration, slotsPerEpoch, err = eth2wrap.FetchSlotsConfig(ctx, eth2Cl)

		return err == nil
	}, time.Minute, time.Second, "fetch chain spec via node %d validator API", peerIdx)

	vmock := validatormock.New(ctx, provider, signer, pubshares, genesisTime, slotDuration, slotsPerEpoch, false)

	go tickSlots(ctx, vmock, genesisTime, slotDuration, slotsPerEpoch)
}

// tickSlots drives the validator mock with wall-clock slot ticks, standing
// in for the scheduler subscription charon uses in-process.
func tickSlots(ctx context.Context, vmock *validatormock.Component, genesisTime time.Time, slotDuration time.Duration, slotsPerEpoch uint64) {
	slotOf := func(now time.Time) core.Slot {
		number := uint64(now.Sub(genesisTime) / slotDuration)

		return core.Slot{
			Slot:          number,
			Time:          genesisTime.Add(time.Duration(number) * slotDuration),
			SlotDuration:  slotDuration,
			SlotsPerEpoch: slotsPerEpoch,
		}
	}

	slot := slotOf(time.Now()).Next()

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(slot.Time)):
			_ = vmock.SlotTicked(ctx, slot)
			slot = slot.Next()
		}
	}
}

// cachedEth2Provider mirrors charon's app.newVMockEth2Provider: a lazy,
// cached eth2 HTTP client against a validator API address.
func cachedEth2Provider(addr string, pubshares []eth2p0.BLSPubKey) func() (eth2wrap.Client, error) {
	var (
		mu     sync.Mutex
		cached eth2wrap.Client
	)

	const timeout = 10 * time.Second

	return func() (eth2wrap.Client, error) {
		mu.Lock()
		defer mu.Unlock()

		if cached != nil {
			return cached, nil
		}

		eth2Svc, err := eth2http.New(context.Background(),
			eth2http.WithLogLevel(1),
			eth2http.WithAddress(addr),
			eth2http.WithTimeout(timeout),
		)
		if err != nil {
			return nil, err
		}

		eth2Http, ok := eth2Svc.(*eth2http.Service)
		if !ok {
			return nil, errors.New("invalid eth2 http service")
		}

		cached = eth2wrap.AdaptEth2HTTP(eth2Http, nil, timeout)
		valCache := eth2wrap.NewValidatorCache(cached, pubshares)
		cached.SetValidatorCache(valCache.GetByHead)

		return cached, nil
	}
}
