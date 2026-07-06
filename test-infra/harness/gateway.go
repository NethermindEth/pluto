package harness

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

// startGateway starts an HTTP beacon-node facade for one node, backed by the
// shared beaconmock. Duty and validator endpoints are served dynamically from
// the mock's Go interface (the mock's own HTTP server only serves static
// stubs), submissions are captured, and everything else is reverse-proxied to
// the mock's HTTP server (static config endpoints plus the SSE event stream).
func startGateway(t *testing.T, bnet *BeaconNet, nodeIdx int) string {
	t.Helper()

	target, err := url.Parse(bnet.Mock.Address())
	require.NoError(t, err)

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1 // Flush immediately so the SSE event stream works.

	g := &gateway{
		bnet:    bnet,
		nodeIdx: nodeIdx,
		proxy:   proxy,
		logf:    t.Logf,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		_ = srv.Serve(listener)
	}()

	t.Cleanup(func() {
		_ = srv.Close()
	})

	return "http://" + listener.Addr().String()
}

type gateway struct {
	bnet    *BeaconNet
	nodeIdx int
	proxy   *httputil.ReverseProxy
	logf    func(format string, args ...any)
}

// submissionPaths are POST endpoints captured for assertions and
// acknowledged with 200 OK without touching the mock.
var submissionPaths = map[string]bool{
	"/eth/v1/beacon/pool/attestations":       true,
	"/eth/v2/beacon/pool/attestations":       true,
	"/eth/v1/validator/aggregate_and_proofs": true,
	"/eth/v2/validator/aggregate_and_proofs": true,
	"/eth/v1/validator/register_validator":   true,
}

// ackPaths are POST endpoints acknowledged with 200 OK without capture.
var ackPaths = map[string]bool{
	"/eth/v1/validator/beacon_committee_subscriptions": true,
	"/eth/v1/validator/sync_committee_subscriptions":   true,
	"/eth/v1/validator/prepare_beacon_proposer":        true,
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	ctx := r.Context()

	switch {
	case submissionPaths[path] && r.Method == http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		g.bnet.record(Submission{
			NodeIdx:          g.nodeIdx,
			Path:             path,
			ConsensusVersion: r.Header.Get("Eth-Consensus-Version"),
			Body:             body,
			At:               time.Now(),
		})
		w.WriteHeader(http.StatusOK)

	case ackPaths[path] && r.Method == http.MethodPost:
		w.WriteHeader(http.StatusOK)

	case strings.HasPrefix(path, "/eth/v1/validator/duties/attester/"):
		g.attesterDuties(w, r)

	case strings.HasPrefix(path, "/eth/v1/validator/duties/proposer/"):
		epoch, ok := epochFromPath(w, path)
		if !ok {
			return
		}

		resp, err := g.bnet.Mock.ProposerDuties(ctx, &eth2api.ProposerDutiesOpts{Epoch: epoch})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, map[string]any{
			"dependent_root":       zeroRootHex(),
			"execution_optimistic": false,
			"data":                 orEmpty(resp.Data),
		})

	case strings.HasPrefix(path, "/eth/v1/validator/duties/sync/"):
		epoch, ok := epochFromPath(w, path)
		if !ok {
			return
		}

		indices, ok := readIndicesBody(w, r)
		if !ok {
			return
		}

		resp, err := g.bnet.Mock.SyncCommitteeDuties(ctx, &eth2api.SyncCommitteeDutiesOpts{Epoch: epoch, Indices: indices})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, map[string]any{
			"execution_optimistic": false,
			"data":                 orEmpty(resp.Data),
		})

	case strings.HasPrefix(path, "/eth/v1/beacon/states/") && strings.HasSuffix(path, "/validators"):
		g.validators(w, r)

	case strings.HasPrefix(path, "/eth/v1/beacon/states/") && strings.HasSuffix(path, "/committees"):
		g.committees(w, r)

	case path == "/eth/v1/validator/attestation_data":
		g.attestationData(w, r)

	case path == "/eth/v1/validator/aggregate_attestation" || path == "/eth/v2/validator/aggregate_attestation":
		g.aggregateAttestation(w, r)

	case path == "/eth/v1/node/peer_count":
		writeJSON(w, map[string]any{
			"data": map[string]string{
				"disconnected":  "0",
				"connecting":    "0",
				"connected":     "8",
				"disconnecting": "0",
			},
		})

	default:
		if r.Method != http.MethodGet {
			g.logf("gateway[node%d]: proxying %s %s", g.nodeIdx, r.Method, path)
		}

		g.proxy.ServeHTTP(w, r)
	}
}

func (g *gateway) attesterDuties(w http.ResponseWriter, r *http.Request) {
	epoch, ok := epochFromPath(w, r.URL.Path)
	if !ok {
		return
	}

	indices, ok := readIndicesBody(w, r)
	if !ok {
		return
	}

	resp, err := g.bnet.Mock.AttesterDuties(r.Context(), &eth2api.AttesterDutiesOpts{Epoch: epoch, Indices: indices})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"dependent_root":       zeroRootHex(),
		"execution_optimistic": false,
		"data":                 orEmpty(resp.Data),
	})
}

func (g *gateway) validators(w http.ResponseWriter, r *http.Request) {
	opts := &eth2api.ValidatorsOpts{State: "head"}

	// Support both GET with ?id=... and POST with {"ids": [...]}.
	var ids []string

	switch r.Method {
	case http.MethodGet:
		if raw := r.URL.Query().Get("id"); raw != "" {
			ids = strings.Split(raw, ",")
		}
	case http.MethodPost:
		var body struct {
			IDs []string `json:"ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ids = body.IDs
	}

	for _, id := range ids {
		id = strings.TrimSpace(id)
		if strings.HasPrefix(id, "0x") {
			var pubkey eth2p0.BLSPubKey
			if err := pubkey.UnmarshalJSON([]byte(strconv.Quote(id))); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			opts.PubKeys = append(opts.PubKeys, pubkey)
		} else {
			idx, err := strconv.ParseUint(id, 10, 64)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			opts.Indices = append(opts.Indices, eth2p0.ValidatorIndex(idx))
		}
	}

	resp, err := g.bnet.Mock.Validators(r.Context(), opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	validators := make([]*eth2v1.Validator, 0, len(resp.Data))
	for _, validator := range resp.Data {
		validators = append(validators, validator)
	}

	sort.Slice(validators, func(i, j int) bool { return validators[i].Index < validators[j].Index })

	writeJSON(w, map[string]any{
		"execution_optimistic": false,
		"finalized":            false,
		"data":                 validators,
	})
}

func (g *gateway) committees(w http.ResponseWriter, r *http.Request) {
	opts := &eth2api.BeaconCommitteesOpts{State: "head"}

	if raw := r.URL.Query().Get("epoch"); raw != "" {
		epoch, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		eth2Epoch := eth2p0.Epoch(epoch)
		opts.Epoch = &eth2Epoch
	}

	resp, err := g.bnet.Mock.BeaconCommittees(r.Context(), opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"execution_optimistic": false,
		"finalized":            false,
		"data":                 orEmpty(resp.Data),
	})
}

func (g *gateway) attestationData(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	slot, err := strconv.ParseUint(query.Get("slot"), 10, 64)
	if err != nil {
		http.Error(w, "invalid slot: "+err.Error(), http.StatusBadRequest)
		return
	}

	// committee_index is optional post-electra, defaulting to zero.
	var committeeIndex uint64
	if raw := query.Get("committee_index"); raw != "" {
		committeeIndex, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			http.Error(w, "invalid committee_index: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	resp, err := g.bnet.Mock.AttestationData(r.Context(), &eth2api.AttestationDataOpts{
		Slot:           eth2p0.Slot(slot),
		CommitteeIndex: eth2p0.CommitteeIndex(committeeIndex),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{"data": resp.Data})
}

func (g *gateway) aggregateAttestation(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	slot, err := strconv.ParseUint(query.Get("slot"), 10, 64)
	if err != nil {
		http.Error(w, "invalid slot: "+err.Error(), http.StatusBadRequest)
		return
	}

	var root eth2p0.Root
	if err := root.UnmarshalJSON([]byte(strconv.Quote(query.Get("attestation_data_root")))); err != nil {
		http.Error(w, "invalid attestation_data_root: "+err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := g.bnet.Mock.AggregateAttestation(r.Context(), &eth2api.AggregateAttestationOpts{
		Slot:                eth2p0.Slot(slot),
		AttestationDataRoot: root,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	version, data, err := versionedAttestationJSON(resp.Data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Eth-Consensus-Version", version)
	writeJSON(w, map[string]any{"version": version, "data": data})
}

// versionedAttestationJSON marshals the inner attestation of a versioned
// attestation and returns its version string.
func versionedAttestationJSON(att *eth2spec.VersionedAttestation) (string, json.RawMessage, error) {
	var inner any

	switch att.Version {
	case eth2spec.DataVersionPhase0:
		inner = att.Phase0
	case eth2spec.DataVersionAltair:
		inner = att.Altair
	case eth2spec.DataVersionBellatrix:
		inner = att.Bellatrix
	case eth2spec.DataVersionCapella:
		inner = att.Capella
	case eth2spec.DataVersionDeneb:
		inner = att.Deneb
	case eth2spec.DataVersionElectra:
		inner = att.Electra
	case eth2spec.DataVersionFulu:
		inner = att.Fulu
	default:
		inner = att.Electra
	}

	data, err := json.Marshal(inner)
	if err != nil {
		return "", nil, err
	}

	return att.Version.String(), data, nil
}

// epochFromPath parses the trailing epoch path segment, writing a 400 on
// failure.
func epochFromPath(w http.ResponseWriter, path string) (eth2p0.Epoch, bool) {
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")

	epoch, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	if err != nil {
		http.Error(w, "invalid epoch: "+err.Error(), http.StatusBadRequest)
		return 0, false
	}

	return eth2p0.Epoch(epoch), true
}

// readIndicesBody reads a JSON array of validator index strings, writing a
// 400 on failure.
func readIndicesBody(w http.ResponseWriter, r *http.Request) ([]eth2p0.ValidatorIndex, bool) {
	var raw []string
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil && err != io.EOF {
		http.Error(w, "invalid indices body: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}

	var indices []eth2p0.ValidatorIndex

	for _, s := range raw {
		idx, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			http.Error(w, "invalid index: "+err.Error(), http.StatusBadRequest)
			return nil, false
		}

		indices = append(indices, eth2p0.ValidatorIndex(idx))
	}

	return indices, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")

	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(b)
}

func zeroRootHex() string {
	return "0x" + strings.Repeat("00", 32)
}

// orEmpty replaces a nil slice with an empty one so it marshals as [] and
// not null.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}

	return s
}
