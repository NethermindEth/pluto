// Package harness provides a Go test harness that runs simnet-style
// end-to-end duty tests over clusters mixing charon nodes (in-process,
// reusing charon's own app and test utilities) and pluto nodes
// (subprocesses of the pluto binary).
//
// It mirrors charon's testutil/integration simnet design: a deterministic
// cluster fixture, an in-process libp2p relay, a mocked beacon chain with
// deterministic duties, and validator mocks driving each node's validator
// API. Unlike upstream simnet, partial-signature exchange always runs over
// real p2p so out-of-process pluto nodes can participate.
package harness

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

// simnetForkVersion is the fork version used by charon's simnet tests. It
// maps to a genesis time via eth2util.ForkVersionToGenesisTime, keeping the
// beaconmock slot clock consistent across all nodes.
var simnetForkVersion = []byte{0x01, 0x01, 0x70, 0x00}

// Fixture is a deterministic distributed-validator cluster shared by all
// nodes in a harness test.
type Fixture struct {
	N         int
	Threshold int
	NumVals   int

	Lock    cluster.Lock
	P2PKeys []*k1.PrivateKey
	// Shares holds BLS secret shares indexed by [validator][node].
	Shares [][]tbls.PrivateKey

	// VAPIAddrs holds one validator-api listen address per node.
	VAPIAddrs []string
}

// NewFixture returns a deterministic cluster fixture generated from seed,
// mirroring charon's testutil/integration simnet arguments.
func NewFixture(t *testing.T, n, threshold, numVals, seed int) *Fixture {
	t.Helper()

	random := rand.New(rand.NewSource(int64(seed)))
	lock, p2pKeys, shares := cluster.NewForT(t, numVals, threshold, n, seed, random, func(definition *cluster.Definition) {
		definition.ForkVersion = simnetForkVersion
	})

	var vapiAddrs []string
	for range n {
		vapiAddrs = append(vapiAddrs, testutil.AvailableAddr(t).String())
	}

	return &Fixture{
		N:         n,
		Threshold: threshold,
		NumVals:   numVals,
		Lock:      lock,
		P2PKeys:   p2pKeys,
		Shares:    shares,
		VAPIAddrs: vapiAddrs,
	}
}

// NodeSecrets returns the BLS secret shares held by node i, one per
// distributed validator.
func (f *Fixture) NodeSecrets(i int) []tbls.PrivateKey {
	var secrets []tbls.PrivateKey
	for _, dv := range f.Shares {
		secrets = append(secrets, dv[i])
	}

	return secrets
}

// NodePubshares returns the public keys of node i's shares, one per
// distributed validator. These are the "validators" a VC connected to the
// node's validator API sees.
func (f *Fixture) NodePubshares(t *testing.T, i int) []eth2p0.BLSPubKey {
	t.Helper()

	var pubshares []eth2p0.BLSPubKey
	for _, secret := range f.NodeSecrets(i) {
		pubkey, err := tbls.SecretToPublicKey(secret)
		require.NoError(t, err)

		pubshares = append(pubshares, eth2p0.BLSPubKey(pubkey))
	}

	return pubshares
}

// DVPubkeys returns the group public key of each distributed validator in
// the lock.
func (f *Fixture) DVPubkeys(t *testing.T) []eth2p0.BLSPubKey {
	t.Helper()

	var pubkeys []eth2p0.BLSPubKey
	for _, validator := range f.Lock.Validators {
		pubkey, err := validator.PublicKey()
		require.NoError(t, err)

		pubkeys = append(pubkeys, eth2p0.BLSPubKey(pubkey))
	}

	return pubkeys
}

// WriteNodeDir writes the on-disk layout a subprocess node expects and
// returns the directory: cluster-lock.json, charon-enr-private-key and
// validator_keys/ with the node's keystore shares.
func (f *Fixture) WriteNodeDir(t *testing.T, i int) string {
	t.Helper()

	dir := t.TempDir()

	lockJSON, err := json.MarshalIndent(f.Lock, "", " ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cluster-lock.json"), lockJSON, 0o644))

	require.NoError(t, k1util.Save(f.P2PKeys[i], filepath.Join(dir, "charon-enr-private-key")))

	keysDir := filepath.Join(dir, "validator_keys")
	require.NoError(t, os.Mkdir(keysDir, 0o755))
	require.NoError(t, keystore.StoreKeysInsecure(f.NodeSecrets(i), keysDir, keystore.ConfirmInsecureKeys))

	return dir
}
