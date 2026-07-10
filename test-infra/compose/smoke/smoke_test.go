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
	plutoRun    = flag.Bool("pluto-run", false, "Enable scenarios that run pluto nodes. Requires `pluto run` support and the PLUTO_REPO env var.")
	sudoPerms   = flag.Bool("sudo-perms", false, "Enables changing all compose artefacts file permissions using sudo.")
	logDir      = flag.String("log-dir", "", "Specifies the directory to store test docker-compose logs. Empty defaults to stdout.")
)

// charonImageTag pins the charon reference version pluto is ported from.
const charonImageTag = "v1.7.1"

func TestSmoke(t *testing.T) {
	if !*integration {
		t.Skip("Skipping smoke integration test")
	}

	const defaultTimeout = time.Minute

	tests := []struct {
		Name            string
		ConfigFunc      func(*compose.Config)
		RunTmplFunc     func(*compose.TmplData)
		DefineTmplFunc  func(*compose.TmplData)
		PrintYML        bool
		Timeout         time.Duration
		RequirePluto    bool // Scenario needs the pluto docker image (PLUTO_REPO env var).
		RequirePlutoRun bool // Scenario runs pluto nodes, which requires `pluto run` support (-pluto-run flag).
	}{
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
				conf.VCs = []compose.VCType{compose.VCMock}
			},
		},
		{
			Name: "very_large",
			ConfigFunc: func(conf *compose.Config) {
				conf.NumNodes = 10
				conf.Threshold = 7
				conf.NumValidators = 100
				conf.KeyGen = compose.KeyGenCreate
				conf.VCs = []compose.VCType{compose.VCMock}
				conf.SlotDuration = time.Second * 6
				conf.SyntheticBlockProposals = false
			},
			Timeout: time.Minute * 2,
		},
		{
			Name: "1_of_4_down",
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
			Name: "1_of_3_down",
			ConfigFunc: func(conf *compose.Config) {
				conf.NumNodes = 3
				conf.Threshold = 2
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
				conf.VCs = []compose.VCType{compose.VCMock}
			},
		},
		{
			Name:            "all_pluto",
			RequirePluto:    true,
			RequirePlutoRun: true,
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.NodeImpls = []compose.NodeImpl{compose.ImplPluto}
				conf.VCs = []compose.VCType{compose.VCMock}
				// `pluto run` fails fast on --synthetic-block-proposals.
				conf.SyntheticBlockProposals = false
			},
		},
		{
			// Threshold 3 of 4 forces both implementations to participate in every duty.
			Name:            "mixed_2_charon_2_pluto",
			RequirePluto:    true,
			RequirePlutoRun: true,
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenCreate
				conf.NodeImpls = []compose.NodeImpl{
					compose.ImplCharon, compose.ImplCharon,
					compose.ImplPluto, compose.ImplPluto,
				}
				conf.VCs = []compose.VCType{compose.VCMock}
				// `pluto run` fails fast on --synthetic-block-proposals.
				conf.SyntheticBlockProposals = false
			},
		},
		{
			Name:            "pluto_dkg",
			RequirePluto:    true,
			RequirePlutoRun: true,
			ConfigFunc: func(conf *compose.Config) {
				conf.KeyGen = compose.KeyGenDKG
				conf.NodeImpls = []compose.NodeImpl{compose.ImplPluto}
				conf.VCs = []compose.VCType{compose.VCMock}
				// `pluto run` fails fast on --synthetic-block-proposals.
				conf.SyntheticBlockProposals = false
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.RequirePluto && os.Getenv("PLUTO_REPO") == "" {
				t.Skip("Skipping pluto scenario since PLUTO_REPO env var is not set")
			}

			if test.RequirePlutoRun && !*plutoRun {
				t.Skip("Skipping scenario running pluto nodes; enable with -pluto-run once `pluto run` is supported")
			}

			dir := t.TempDir()

			conf := compose.NewDefaultConfig()
			conf.Monitoring = false
			conf.DisableMonitoringPorts = true
			conf.ImageTag = charonImageTag

			conf.InsecureKeys = true
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
