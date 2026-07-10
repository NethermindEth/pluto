// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
)

// Lock creates a docker-compose.yml from a charon-compose.yml for generating keys and a cluster lock file.
func Lock(ctx context.Context, dir string, conf Config) (TmplData, error) {
	if conf.Step != stepDefined {
		return TmplData{}, errors.New("compose config not defined, so can't be locked", z.Any("step", conf.Step))
	}

	var data TmplData

	switch conf.KeyGen {
	case KeyGenCreate:
		splitKeysDir, err := getRelSplitKeysDir(dir, conf.SplitKeysDir)
		if err != nil {
			return TmplData{}, err
		} else if splitKeysDir != "" {
			splitKeysDir = path.Join("/compose", splitKeysDir)
		}

		// Only single node to call charon create cluster generate keys
		kvs := []kv{
			{"name", fmt.Sprintf("compose-%d-%d", conf.NumNodes, conf.NumValidators)},
			{"threshold", strconv.Itoa(conf.Threshold)},
			{"nodes", strconv.Itoa(conf.NumNodes)},
			{"cluster-dir", "/compose"},
			{"split-existing-keys", fmt.Sprintf(`"%v"`, conf.SplitKeysDir != "")},
			{"split-keys-dir", splitKeysDir},
			{"num-validators", strconv.Itoa(conf.NumValidators)},
			{"insecure-keys", fmt.Sprintf(`"%v"`, conf.InsecureKeys)},
			{"withdrawal-addresses", zeroAddress},
			{"fee-recipient-addresses", zeroAddress},
			{"network", eth2util.Goerli.Name},
		}

		n := TmplNode{Image: conf.ImageOverride(conf.KeygenImpl()), EnvVars: kvs}
		if conf.KeygenImpl() == ImplPluto {
			n.Command = flagsCommand(cmdCreateCluster, kvs)
		}

		data = TmplData{
			ComposeDir:     dir,
			CharonImageTag: conf.ImageTag,
			CharonCommand:  cmdCreateCluster,
			Nodes:          []TmplNode{n},
		}
	case KeyGenDKG:
		var nodes []TmplNode
		for i := range conf.NumNodes {
			n := TmplNode{
				EnvVars: newNodeEnvs(i, conf, ""),
				Image:   conf.ImageOverride(conf.NodeImpl(i)),
				Command: cmdDKG,
			}
			nodes = append(nodes, n)
		}

		data = TmplData{
			ComposeDir:     dir,
			CharonImageTag: conf.ImageTag,
			CharonCommand:  "not used",
			Relay:          true,
			Nodes:          nodes,
		}
	default:
		return TmplData{}, errors.New("unsupported keygen", z.Any("keygen", conf.KeyGen))
	}

	log.Info(ctx, "Creating docker-compose.yml")
	log.Info(ctx, "Create keys and cluster lock with: docker compose up")

	conf.Step = stepLocked
	if err := WriteConfig(dir, conf); err != nil {
		return TmplData{}, err
	}

	if err := WriteDockerCompose(dir, data); err != nil {
		return TmplData{}, err
	}

	return data, nil
}

// newNodeEnvs returns the default node environment variable to run a charon docker container.
func newNodeEnvs(index int, conf Config, vcType VCType) []kv {
	beaconMock := false

	beaconNode := conf.BeaconNodes
	if beaconNode == "mock" {
		beaconMock = true
		beaconNode = ""
	}

	lockFile := fmt.Sprintf("/compose/node%d/cluster-lock.json", index)

	// The path-less URL form (multiaddrs response) instead of charon-compose's
	// /enr path: pluto's relay parsing roundtrips URLs through a multiaddr,
	// which cannot represent a URL path. Charon supports both forms.
	//nolint:revive // tls not required for testing.
	p2pRelayAddr := "http://relay:3640"
	if conf.ExternalRelay != "" {
		p2pRelayAddr = conf.ExternalRelay
	}

	// Common config
	kvs := []kv{
		{"private-key-file", fmt.Sprintf("/compose/node%d/charon-enr-private-key", index)},
		{"monitoring-address", "0.0.0.0:3620"},
		{"p2p-external-hostname", fmt.Sprintf("node%d", index)},
		{"p2p-tcp-address", "0.0.0.0:3610"},
		{"p2p-relays", p2pRelayAddr},
		{"log-level", "debug"},
		{"log-color", "force"},
		{"feature-set", conf.FeatureSet},
	}

	if conf.Step == stepDefined {
		// Define lock config
		return append(kvs,
			kv{"data-dir", fmt.Sprintf("/compose/node%d", index)},
			kv{"definition-file", "/compose/cluster-definition.json"},
			kv{"insecure-keys", fmt.Sprintf(`"%v"`, conf.InsecureKeys)},
		)
	}

	// Define run config
	kvs = append(kvs,
		kv{"lock-file", lockFile},
		kv{"validator-api-address", "0.0.0.0:3600"},
		kv{"beacon-node-endpoints", beaconNode},
		kv{"simnet-beacon_mock", fmt.Sprintf(`"%v"`, beaconMock)},
		kv{"simnet-validator-mock", fmt.Sprintf(`"%v"`, vcType == VCMock)},
		kv{"simnet-slot-duration", conf.SlotDuration.String()},
		kv{"simnet-validator-keys-dir", fmt.Sprintf("/compose/node%d/validator_keys", index)},
		kv{"simnet-beacon-mock-fuzz", fmt.Sprintf(`"%v"`, conf.BeaconFuzz)},
		kv{"synthetic-block-proposals", fmt.Sprintf(`"%v"`, conf.SyntheticBlockProposals)},
		kv{"builder-api", fmt.Sprintf(`"%v"`, conf.BuilderAPI)},
	)

	// Unlike charon's compose, only point nodes at loki/tempo when the
	// monitoring stack actually runs: failed pushes to absent services are
	// logged as errors, tripping the Error Log Rate alert.
	if conf.Monitoring {
		//nolint:revive // tls not required for testing.
		kvs = append(kvs,
			kv{"otlp-address", "tempo:4317"},
			kv{"otlp-service-name", fmt.Sprintf("node%d", index)},
			kv{"loki-addresses", "http://loki:3100/loki/api/v1/push"},
			kv{"loki-service", fmt.Sprintf("node%d", index)},
		)
	}

	return kvs
}

// LoadConfig returns the config loaded from disk.
func LoadConfig(dir string) (Config, error) {
	b, err := os.ReadFile(path.Join(dir, configFile))
	if err != nil {
		return Config{}, errors.Wrap(err, "load config")
	}

	var resp Config
	if err := json.Unmarshal(b, &resp); err != nil {
		return Config{}, errors.Wrap(err, "unmarshal Config")
	}

	return resp, nil
}
