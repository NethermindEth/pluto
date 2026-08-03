// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package smoke_test

import (
	"context"
	"flag"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"

	"github.com/NethermindEth/pluto/test-infra/compose"
)

//go:generate go test . -run=TestSmoke -integration -v

var (
	integration = flag.Bool("integration", false, "Enable docker based integration test")
	sudoPerms   = flag.Bool("sudo-perms", false, "Enables changing all compose artefacts file permissions using sudo.")
	logDir      = flag.String("log-dir", "", "Specifies the directory to store test docker-compose logs. Empty defaults to stdout.")
)

// charonImageTag pins the charon reference version pluto is ported from.
const charonImageTag = "v1.7.1"

// defaultTimeout bounds one scenario's alert collection: Prometheus readiness
// (~10s) + the 60s cold-start warmup (compose/alert.go) + steady-state
// polling time beyond it.
const defaultTimeout = 2 * time.Minute

// smokeBaseConfig returns the config every scenario starts from.
//
// All scenarios run the mock validator client: charon v1.7.1's beaconmock
// hardcodes `head_slot: "1"` in /eth/v1/node/syncing, so a real VC (e.g.
// lighthouse) permanently considers the beacon node unsynced and performs no
// duties — the cluster then never reaches the signing threshold and the
// broadcast/error alerts fire by design. Upstream charon runs lighthouse VCs
// in these scenarios but never noticed because its alert gate matches a
// state ("active") that Prometheus never reports. The real-VC compose
// service definitions remain in the harness (`static/`), but the tests
// always run the mock VC.
func smokeBaseConfig() compose.Config {
	conf := compose.NewDefaultConfig()
	conf.Monitoring = false
	conf.DisableMonitoringPorts = true
	conf.ImageTag = charonImageTag
	conf.InsecureKeys = true
	conf.VCs = []compose.VCType{compose.VCMock}

	// Route the cluster through an external relay (e.g. the public
	// https://0.relay.obol.tech) instead of the local relay container. The
	// local relay service still runs so its prometheus scrape target stays
	// up; nothing dials it.
	if url := os.Getenv("SMOKE_EXTERNAL_RELAY"); url != "" {
		conf.ExternalRelay = url
	}

	return conf
}

// smokeScenario defines one smoke matrix entry.
type smokeScenario struct {
	Name           string
	ConfigFunc     func(*compose.Config)
	RunTmplFunc    func(*compose.TmplData)
	DefineTmplFunc func(*compose.TmplData)
	PrintYML       bool
	Timeout        time.Duration
	RequirePluto   bool // Scenario needs the pluto docker image (PLUTO_REPO env var).
}

// smokeScenarios returns the full scenario matrix. Every scenario runs when
// -integration is set; the only skip condition is a pluto scenario without
// the PLUTO_REPO env var.
func smokeScenarios() []smokeScenario {
	return []smokeScenario{
		{
			Name:     "default_alpha",
			PrintYML: true,
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.FeatureSet = "alpha"
			},
		},
		{
			Name: "default_beta",
			ConfigFunc: func(conf *compose.Config) {
				conf.NumNodes = 3
				conf.Threshold = 2
				conf.KeyGen = compose.KeyGenCreate
				conf.FeatureSet = "beta"
			},
		},
		{
			Name: "default_stable",
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.FeatureSet = "stable"
			},
		},
		{
			Name: "dkg",
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenDKG
			},
		},
		{
			Name: "very_large",
			ConfigFunc: func(conf *compose.Config) {
				conf.NumNodes = 10
				conf.Threshold = 7
				conf.NumValidators = 100
				conf.KeyGen = compose.KeyGenCreate
				conf.SlotDuration = time.Second * 6
				conf.SyntheticBlockProposals = false
			},
			Timeout: time.Minute * 3,
		},
		{
			// node0 keeps default p2p flags (public relays) so it runs but
			// cannot reach the cluster: expected to log errors and stop
			// broadcasting, hence exempted from the per-node behavioral
			// alerts (not from "Pluto Down").
			//
			// This scenario gates liveness only — that losing a node does not
			// take the rest of the cluster down. It deliberately does NOT
			// gate duty outcomes, because at simnet settings the surviving
			// three cannot reliably complete duties and no configuration
			// fixes that:
			//
			//   - Charon derives duty deadlines from slot duration (a
			//     proposer duty must finish within slotDuration/3), leaving
			//     ~0.33s at the 1s default. QBFT quorum for n=4 is 3, so with
			//     node0 down every duty needs all three survivors inside that
			//     window with no slack. Measured: ~40% of runs failed (2/5),
			//     the survivors logging consensus timeouts, `propose_block_v3`
			//     validator-API errors, and broadcast gaps — three symptoms of
			//     one cause, so silencing them individually just moves it.
			//   - Slowing slots to 3s fixes the deadlines but stretches epochs
			//     to 48s, and with one validator the duties no longer land in
			//     every 30s alert window. Measured: 3/4 runs failed on
			//     `Broadcast Duty Rate`.
			//
			// So the duty-outcome rules are dropped and the remainder is kept
			// honest: every node stays scrapable (`Pluto Down`, never
			// excluded) and nothing floods the warn log — which is what
			// "survives 1 of 4 down" can actually assert here. node0 is also
			// exempted from the per-node behavioral rules via
			// AlertExcludeJobs, since it is expected to error and go silent.
			Name: "1_of_4_down",
			ConfigFunc: func(conf *compose.Config) {
				conf.AlertExcludeJobs = []string{"node0"}
				conf.AlertDisableRules = []string{
					"Error Log Rate",
					"Validator API Error Rate",
					"Broadcast Duty Rate",
				}
			},
			RunTmplFunc: func(data *compose.TmplData) {
				node0 := data.Nodes[0]
				for i := range len(node0.EnvVars) {
					if strings.HasPrefix(node0.EnvVars[i].Key, "p2p") {
						data.Nodes[0].EnvVars[i].Key = node0.EnvVars[i].Key + "-unset" // Zero p2p flags to it cannot communicate
					}
				}
			},
		},
		{
			// Same collateral-error problem as 1_of_4_down (see there), but
			// worse: with 3 nodes even the epoch-aligned proposer duties
			// rotate their round-1 leader (16 % 3 == 1), so every third one
			// is led by the downed node0 and cannot recover — charon
			// v1.7.1's linear round timer uses nanosecond timeouts after
			// round 1 (upstream bug #4537) and the 1s-slot proposer deadline
			// (~0.4s) expires regardless. The HEALTHY nodes therefore log
			// both consensus timeouts and failing vmock proposal requests,
			// so the validator-API error gate is dropped too. Broadcast
			// liveness, warn rates, and scrape health stay gated.
			Name: "1_of_3_down",
			ConfigFunc: func(conf *compose.Config) {
				conf.NumNodes = 3
				conf.Threshold = 2
				conf.AlertExcludeJobs = []string{"node0"}
				conf.AlertDisableRules = []string{"Error Log Rate", "Validator API Error Rate"}
			},
			RunTmplFunc: func(data *compose.TmplData) {
				node0 := data.Nodes[0]
				for i := range len(node0.EnvVars) {
					if strings.HasPrefix(node0.EnvVars[i].Key, "p2p") {
						data.Nodes[0].EnvVars[i].Key = node0.EnvVars[i].Key + "-unset" // Zero p2p flags to it cannot communicate
					}
				}
			},
		},
		{
			Name: "blinded_blocks_vmock",
			ConfigFunc: func(conf *compose.Config) {
				conf.BuilderAPI = true
			},
		},
		{
			// Pluto generates the keys and cluster lock, charon nodes run them.
			// Validates pluto `create cluster` artifacts against the charon runtime.
			Name:         "pluto_keygen_create",
			RequirePluto: true,
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.KeyGenImpl = compose.ImplPluto
			},
		},
		{
			Name:         "all_pluto",
			RequirePluto: true,
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.NodeImpls = []compose.NodeImpl{compose.ImplPluto}
				// `pluto run` fails fast on --synthetic-block-proposals.
				conf.SyntheticBlockProposals = false
			},
		},
		{
			// Threshold 3 of 4 forces both implementations to participate in every duty.
			Name:         "mixed_2_charon_2_pluto",
			RequirePluto: true,
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.NodeImpls = []compose.NodeImpl{
					compose.ImplCharon, compose.ImplCharon,
					compose.ImplPluto, compose.ImplPluto,
				}
				// `pluto run` fails fast on --synthetic-block-proposals.
				conf.SyntheticBlockProposals = false
				// Charon triggers infosync (/charon/priority/2.0.0) every
				// epoch; pluto does not serve the protocol yet (#402B), so
				// charon nodes warn "P2P sending failing" under topic=sched
				// twice per epoch. Exempt that topic in mixed clusters until
				// the protocol lands; drop this with #402B.
				conf.AlertWarnExcludeTopics = []string{"sched"}
			},
		},
		{
			Name:         "pluto_dkg",
			RequirePluto: true,
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenDKG
				conf.NodeImpls = []compose.NodeImpl{compose.ImplPluto}
				// `pluto run` fails fast on --synthetic-block-proposals.
				conf.SyntheticBlockProposals = false
			},
		},
	}
}

func TestSmoke(t *testing.T) {
	if !*integration {
		t.Skip("Skipping smoke integration test")
	}

	for _, test := range smokeScenarios() {
		t.Run(test.Name, func(t *testing.T) {
			if test.RequirePluto && os.Getenv("PLUTO_REPO") == "" {
				t.Skip("Skipping pluto scenario since PLUTO_REPO env var is not set")
			}

			dir := t.TempDir()

			conf := smokeBaseConfig()
			if test.ConfigFunc != nil {
				test.ConfigFunc(&conf)
			}

			require.NoError(t, compose.WriteConfig(dir, conf))

			os.Args = []string{"cobra.test"}

			if test.Timeout == 0 {
				test.Timeout = defaultTimeout
			}

			autoConfig := compose.AutoConfig{
				Dir:            dir,
				AlertTimeout:   test.Timeout,
				SudoPerms:      *sudoPerms,
				PrintYML:       test.PrintYML,
				RunTmplFunc:    test.RunTmplFunc,
				DefineTmplFunc: test.DefineTmplFunc,
			}

			if *logDir != "" {
				autoConfig.LogFile = path.Join(*logDir, test.Name+".log")
			}

			err := compose.Auto(context.Background(), autoConfig)
			testutil.RequireNoError(t, err)
		})
	}
}

// TestScenarioMatrix guards the scenario table invariants without docker:
// unique names, valid configs, and the RequirePluto gate matching the impls a
// scenario actually uses — a pluto scenario without the gate would fail on
// missing PLUTO_REPO (or silently run a stale pluto:local image), and a
// charon-only scenario with the gate would skip for no reason.
func TestScenarioMatrix(t *testing.T) {
	seen := make(map[string]bool)

	for _, test := range smokeScenarios() {
		require.NotEmpty(t, test.Name)
		require.False(t, seen[test.Name], "duplicate scenario name: %s", test.Name)
		seen[test.Name] = true

		conf := smokeBaseConfig()
		if test.ConfigFunc != nil {
			test.ConfigFunc(&conf)
		}

		require.Equal(t, test.RequirePluto, conf.UsesPluto(),
			"RequirePluto must match the implementations scenario %q uses", test.Name)

		// Every scenario config must survive the write/load validation boundary.
		dir := t.TempDir()
		require.NoError(t, compose.WriteConfig(dir, conf))
		_, err := compose.LoadConfig(dir)
		require.NoError(t, err)
	}
}
