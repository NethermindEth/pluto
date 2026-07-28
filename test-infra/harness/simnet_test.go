package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/relay"
)

// scenario describes one simnet cluster composition.
type scenario struct {
	charonNodes int
	plutoNodes  int
	threshold   int
	mode        CharonMode
}

// TestSimnetAttesterCharonInProcess is the baseline: an all-charon cluster
// using charon's in-process beaconmock, mirroring upstream simnet except
// partial-signature exchange runs over real p2p. It validates the fixture,
// relay and assertion plumbing independently of the beacon gateway.
func TestSimnetAttesterCharonInProcess(t *testing.T) {
	runSimnet(t, scenario{charonNodes: 3, threshold: 3, mode: CharonInProcessBMock})
}

// TestSimnetAttesterCharonViaGateway runs an all-charon cluster against the
// harness beacon gateways over real HTTP. Charon here stands in for any
// external node, proving the gateway serves a complete-enough beacon API
// for a distributed validator client before pluto ever connects to it.
func TestSimnetAttesterCharonViaGateway(t *testing.T) {
	runSimnet(t, scenario{charonNodes: 3, threshold: 3, mode: CharonViaGateway})
}

// TestSimnetAttesterPluto runs an all-pluto cluster. Skipped until the
// pluto binary supports `pluto run`.
func TestSimnetAttesterPluto(t *testing.T) {
	runSimnet(t, scenario{plutoNodes: 3, threshold: 3})
}

// TestSimnetAttesterMixed runs 2 charon + 2 pluto nodes with threshold 3,
// forcing cross-implementation participation in every duty. Skipped until
// the pluto binary supports `pluto run`.
func TestSimnetAttesterMixed(t *testing.T) {
	runSimnet(t, scenario{charonNodes: 2, plutoNodes: 2, threshold: 3, mode: CharonViaGateway})
}

// expectedDuties are the duty types every peer must complete in the
// attester flow, mirroring upstream simnet's "attester with mock VCs".
func expectedDuties() []core.DutyType {
	return []core.DutyType{core.DutyPrepareAggregator, core.DutyAttester, core.DutyAggregator}
}

const (
	simnetSeed   = 99
	numVals      = 1
	assertPeriod = 3 * time.Minute
)

func runSimnet(t *testing.T, s scenario) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping simnet test in short mode")
	}

	var plutoBin string
	if s.plutoNodes > 0 {
		plutoBin = SkipUnlessPluto(t)
	}

	n := s.charonNodes + s.plutoNodes

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fixture := NewFixture(t, n, s.threshold, numVals, simnetSeed)

	// Pluto's rust-libp2p relay client rejects the empty-address circuit
	// reservations that a loopback-bound go-libp2p (charon) relay issues, so
	// scenarios involving pluto nodes use a pluto relay, which advertises its
	// loopback address. All-charon scenarios keep the charon relay.
	var relayAddr string
	if s.plutoNodes > 0 {
		relayAddr = StartPlutoRelay(t, ctx, plutoBin)
	} else {
		relayAddr = relay.StartRelay(ctx, t)
	}

	var bnet *BeaconNet

	needGateway := s.plutoNodes > 0 || s.mode == CharonViaGateway
	if needGateway {
		bnet = StartBeaconNet(t, ctx, fixture)
	}

	var (
		eg      errgroup.Group
		results = make(chan SimResult)
	)

	for i := range s.charonNodes {
		var gatewayAddr string
		if s.mode == CharonViaGateway {
			gatewayAddr = bnet.GatewayAddrs[i]
		}

		StartCharonNode(t, ctx, &eg, cancel, fixture, i, relayAddr, s.mode, gatewayAddr, results)
	}

	var plutoNodes []*PlutoNode

	for j := range s.plutoNodes {
		peerIdx := s.charonNodes + j
		node := StartPlutoNode(t, ctx, fixture, peerIdx, plutoBin, relayAddr, bnet.GatewayAddrs[peerIdx])
		plutoNodes = append(plutoNodes, node)
	}

	// Pluto nodes have no in-process validator mock: wait for their
	// validator API and drive one over HTTP.
	for _, node := range plutoNodes {
		node.WaitReady(t, ctx, 2*time.Minute)
		StartValidatorMock(t, ctx, fixture, node.Idx)
	}

	var asserted bool

	if needGateway {
		go drainResults(ctx, t, results)

		asserted = assertCapturedAttestations(t, ctx, bnet, n)
		cancel()
	} else {
		asserted = assertBroadcasts(t, ctx, cancel, fixture, results, n)
	}

	// Surface node errors first: they are the root cause when assertions
	// could not complete because a node exited early.
	err := eg.Wait()
	testutil.SkipIfBindErr(t, err)
	testutil.RequireNoError(t, err)

	if !asserted {
		t.Fatalf("nodes exited without error before all duties were asserted")
	}
}

// assertBroadcasts mirrors upstream simnet's assertion: every peer must
// broadcast every expected duty type, and for each duty all peers must
// produce identical signed data under the DV group public key.
func assertBroadcasts(t *testing.T, ctx context.Context, cancel context.CancelFunc, fixture *Fixture, results <-chan SimResult, n int) bool {
	t.Helper()

	remaining := make(map[core.DutyType]map[int]bool)
	for _, typ := range expectedDuties() {
		remaining[typ] = make(map[int]bool)
		for i := range n {
			remaining[typ][i] = true
		}
	}

	firstData := make(map[core.Duty][]byte)
	firstSig := make(map[core.Duty]core.Signature)
	timeout := time.After(assertPeriod)

	for {
		var res SimResult
		select {
		case <-timeout:
			t.Errorf("timed out waiting for duties, remaining=%v", remaining)
			return false
		case <-ctx.Done():
			return false // A node exited early; its error surfaces via eg.Wait.
		case res = <-results:
		}

		data, err := res.Data.MarshalJSON()
		require.NoError(t, err)

		if prev, ok := firstData[res.Duty]; !ok {
			firstData[res.Duty] = data
			firstSig[res.Duty] = res.Data.Signature()
		} else {
			require.JSONEq(t, string(prev), string(data), "mismatching data for duty %v", res.Duty)
			require.Equal(t, firstSig[res.Duty], res.Data.Signature(), "mismatching signature for duty %v", res.Duty)
			require.EqualValues(t, fixture.Lock.Validators[0].PublicKeyHex(), res.Pubkey)
		}

		if peers, ok := remaining[res.Duty.Type]; ok {
			delete(peers, res.PeerIdx)
			if len(peers) == 0 {
				delete(remaining, res.Duty.Type)
			}

			t.Logf("asserted duty %v from peer %d, remaining=%v", res.Duty, res.PeerIdx, remaining)
		}

		if len(remaining) == 0 {
			cancel()
			return true
		}
	}
}

// drainResults keeps charon broadcast callbacks from blocking in
// capture-asserted scenarios.
func drainResults(ctx context.Context, t *testing.T, results <-chan SimResult) {
	t.Helper()

	for {
		select {
		case <-ctx.Done():
			return
		case res := <-results:
			t.Logf("broadcast from peer %d: %v", res.PeerIdx, res.Duty)
		}
	}
}

// assertCapturedAttestations polls gateway captures until, for some slot,
// every node has submitted an attestation and all submitted payloads are
// identical after JSON normalization (implementations may order keys
// differently).
func assertCapturedAttestations(t *testing.T, ctx context.Context, bnet *BeaconNet, n int) bool {
	t.Helper()

	deadline := time.Now().Add(assertPeriod)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		bySlot := make(map[string]map[int]string) // slot -> nodeIdx -> normalized body

		for _, sub := range bnet.Submissions() {
			if !strings.Contains(sub.Path, "pool/attestations") {
				continue
			}

			slot, normalized, err := normalizeAttestations(sub.Body)
			if err != nil {
				t.Fatalf("malformed attestation submission from node %d: %v\nbody: %s", sub.NodeIdx, err, sub.Body)
			}

			if bySlot[slot] == nil {
				bySlot[slot] = make(map[int]string)
			}

			bySlot[slot][sub.NodeIdx] = normalized
		}

		for slot, byNode := range bySlot {
			if len(byNode) < n {
				continue
			}

			var first string
			for idx, body := range byNode {
				if first == "" {
					first = body
					continue
				}

				require.JSONEq(t, first, body, "node %d submitted a different attestation for slot %s", idx, slot)
			}

			t.Logf("all %d nodes submitted identical attestations for slot %s", n, slot)

			return true
		}

		time.Sleep(500 * time.Millisecond)
	}

	if ctx.Err() != nil {
		return false // A node exited early; its error surfaces via eg.Wait.
	}

	var summary []string
	for _, sub := range bnet.Submissions() {
		summary = append(summary, fmt.Sprintf("node%d %s at %s", sub.NodeIdx, sub.Path, sub.At.Format(time.TimeOnly)))
	}

	t.Errorf("timed out waiting for attestations from all %d nodes; captured:\n%s", n, strings.Join(summary, "\n"))

	return false
}

// normalizeAttestations parses a pool/attestations submission body and
// returns the slot of the first attestation plus the canonical
// re-marshalled body.
func normalizeAttestations(body []byte) (slot string, normalized string, err error) {
	var atts []struct {
		Data struct {
			Slot string `json:"slot"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &atts); err != nil {
		return "", "", err
	}

	if len(atts) == 0 {
		return "", "", fmt.Errorf("empty attestation submission")
	}

	var generic any
	if err := json.Unmarshal(body, &generic); err != nil {
		return "", "", err
	}

	canonical, err := json.Marshal(generic)
	if err != nil {
		return "", "", err
	}

	return atts[0].Data.Slot, string(canonical), nil
}
