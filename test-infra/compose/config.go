// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

import (
	"fmt"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	version           = "obol/charon/compose/1.0.0"
	configFile        = "config.json"
	defaultImageTag   = "latest"
	defaultBeaconNode = "mock"
	defaultKeyGen     = KeyGenCreate
	defaultNumVals    = 1
	defaultNumNodes   = 4
	defaultThreshold  = 3
	defaultFeatureSet = "alpha"

	charonImage  = "obolnetwork/charon"
	plutoImage   = "pluto"
	cmdRun       = "run"
	cmdUnsafeRun = "[unsafe,run]"
	// cmdDKG delays shutdown after completion to allow other nodes to finish.
	// Uses a flag instead of charon's `sh -c '... && sleep 2'` since the pluto image is distroless (no shell).
	cmdDKG           = "[dkg,--shutdown-delay=2s]"
	cmdCreateCluster = "[create,cluster]"
	cmdCreateDKG     = "[create,dkg]"
)

var charonPorts = []port{
	{External: 3600, Internal: 3600}, // # Validator API
	{External: 3610, Internal: 3610}, // # Libp2p
	{External: 3620, Internal: 3620}, // # Monitoring
	{External: 3630, Internal: 3630}, // # Discv5
}

// VCType defines a validator client type.
type VCType string

const (
	VCMock       VCType = "mock"
	VCTeku       VCType = "teku"
	VCLighthouse VCType = "lighthouse"
	VCVouch      VCType = "vouch"
	VCLodestar   VCType = "lodestar"
)

// KeyGen defines a key generation process.
type KeyGen string

const (
	KeyGenDKG    KeyGen = "dkg"
	KeyGenCreate KeyGen = "create"
)

// NodeImpl defines the implementation (charon or pluto) running a node.
type NodeImpl string

const (
	ImplCharon NodeImpl = "charon"
	ImplPluto  NodeImpl = "pluto"
)

// step defines the current completed compose step.
type step string

const (
	stepNew     step = "new"
	stepDefined step = "defined"
	stepLocked  step = "locked"
)

// Config defines a local compose cluster; including both keygen and running a cluster.
type Config struct {
	// Version defines the compose config version.
	Version string `json:"version"`

	// Step defines the current completed compose step.
	Step step `json:"step"`

	// NumNodes is the number of charon nodes in the cluster.
	NumNodes int `json:"num_nodes"`

	// Threshold required for signature reconstruction. Defaults to safe value for number of nodes/peers.
	Threshold int `json:"threshold"`

	// NumValidators is the number of DVs to be created in the cluster lock file.
	NumValidators int `json:"num_validators"`

	// ImageTag defines the charon docker image tag: obolnetwork/charon:{ImageTag}.
	ImageTag string `json:"image_tag"`

	// BuildLocal enables building a local charon docker container from source overriding ImageTag with 'local'.
	BuildLocal bool `json:"build_local"`

	// NodeImpls defines the implementation (charon or pluto) of each node.
	// Nodes are assigned round-robin like VCs; node{i} runs NodeImpls[i%len(NodeImpls)].
	// Empty defaults to all charon.
	NodeImpls []NodeImpl `json:"node_impls"`

	// KeyGenImpl defines the implementation running single-container keygen steps
	// (`create cluster` and `create dkg`). Empty defaults to the implementation of node0.
	KeyGenImpl NodeImpl `json:"keygen_impl"`

	// PlutoImageTag defines the pluto docker image tag: pluto:{PlutoImageTag}.
	// The image is built from source (PLUTO_REPO env var) by the define step when a pluto impl is used.
	PlutoImageTag string `json:"pluto_image_tag"`

	// KeyGen defines the key generation process.
	KeyGen KeyGen `json:"key_gen"`

	// SplitKeysDir directory containing keys to split for keygen==create.
	SplitKeysDir string `json:"split_keys_dir"`

	// BeaconNodes url endpoint or "mock" for simnet.
	BeaconNodes string `json:"beacon_nodes"`

	// ExternalRelay HTTP url endpoint or empty to disable.
	ExternalRelay string `json:"external_relay"`

	// VCs define the types of validator clients to use.
	VCs []VCType `json:"validator_clients"`

	// FeatureSet defines the minimum feature set to enable.
	FeatureSet string `json:"feature_set"`

	// DisableMonitoringPorts defines whether to disable prometheus and jaeger monitoring port binding.
	DisableMonitoringPorts bool `json:"disable_monitoring_ports"`

	// InsecureKeys generates insecure keys. Useful when testing large validator sets
	// as it speeds up keystore encryption and decryption.
	InsecureKeys bool `json:"insecure_keys"`

	// SlotDuration configures slot duration on simnet beacon mock for all the nodes in the cluster.
	SlotDuration time.Duration `json:"slot_duration"`

	// BeaconFuzz configures simnet beaconmock to return fuzzed responses.
	BeaconFuzz bool `json:"beacon-fuzz"`

	// P2PFuzz configures charon p2p network to send and receive fuzzed messages.
	P2PFuzz bool `json:"p2p-fuzz"`

	// SyntheticBlockProposals configures use of synthetic block proposals in simnet cluster.
	SyntheticBlockProposals bool `json:"synthetic_block_proposals"`

	// Monitoring enables monitoring stack for the compose cluster. It includes grafana, loki and jaeger services.
	Monitoring bool `json:"monitoring"`

	// BuilderAPI enables the builder API for the compose cluster.
	BuilderAPI bool `json:"builder_api"`

	// AlertExcludeJobs exempts prometheus jobs (nodes) from the per-node
	// behavioral alert rules (log rates, validator API rates, broadcast
	// liveness) — the "Pluto Down" scrape check still applies. Used by smoke
	// scenarios that deliberately degrade a node (e.g. 1_of_4_down isolates
	// node0 from the p2p network): the degraded node is expected to log
	// errors and stop broadcasting, while the rest of the cluster must stay
	// clean.
	AlertExcludeJobs []string `json:"alert_exclude_jobs,omitempty"`

	// AlertDisableRules drops entire alert rules (by name, see
	// alertRuleNames) from the generated rules. Last-resort scenario knob
	// for cluster-wide degradation that per-job exclusion cannot express:
	// e.g. 1_of_3_down disables the error-rate gates because every third
	// epoch-boundary proposer duty is round-1-led by the downed node and
	// charon v1.7.1 cannot recover it (linear-timer bug #4537 plus the
	// 1s-slot proposer deadline), so the HEALTHY nodes log the collateral
	// consensus timeouts.
	AlertDisableRules []string `json:"alert_disable_rules,omitempty"`
}

// Validate rejects configs with unknown implementation names. It runs on
// every config write and load so a typo (e.g. --node-impls=plutoo) fails
// fast instead of silently selecting the charon image.
func (c Config) Validate() error {
	validImpl := func(impl NodeImpl) bool {
		return impl == ImplCharon || impl == ImplPluto
	}

	for i, impl := range c.NodeImpls {
		if !validImpl(impl) {
			return errors.New("unknown node implementation; must be charon or pluto",
				z.Str("impl", string(impl)), z.Int("index", i))
		}
	}

	// Empty defaults to node0's implementation.
	if c.KeyGenImpl != "" && !validImpl(c.KeyGenImpl) {
		return errors.New("unknown keygen implementation; must be charon or pluto",
			z.Str("impl", string(c.KeyGenImpl)))
	}

	for _, rule := range c.AlertDisableRules {
		if !alertRuleNames[rule] {
			return errors.New("unknown alert rule name in alert_disable_rules",
				z.Str("rule", rule))
		}
	}

	return nil
}

// VCStrings returns the VCs field as a slice of strings.
func (c Config) VCStrings() []string {
	var resp []string
	for _, vc := range c.VCs {
		resp = append(resp, string(vc))
	}

	return resp
}

// NodeImpl returns the implementation of node{index}, assigned round-robin like VCs.
func (c Config) NodeImpl(index int) NodeImpl {
	if len(c.NodeImpls) == 0 {
		return ImplCharon
	}

	return c.NodeImpls[index%len(c.NodeImpls)]
}

// KeygenImpl returns the implementation running single-container keygen steps.
func (c Config) KeygenImpl() NodeImpl {
	if c.KeyGenImpl != "" {
		return c.KeyGenImpl
	}

	return c.NodeImpl(0)
}

// ImplImage returns the full docker image reference for the provided implementation.
func (c Config) ImplImage(impl NodeImpl) string {
	switch impl {
	case ImplPluto:
		return plutoImage + ":" + c.PlutoImageTag
	case ImplCharon:
		return charonImage + ":" + c.ImageTag
	default:
		// Impls are validated on config write and load (Validate); reaching
		// here means a code path bypassed that boundary.
		panic(fmt.Sprintf("bug: unvalidated node implementation %q", impl))
	}
}

// ImageOverride returns the per-node image override for the provided implementation,
// or empty to use the default charon node-base image.
func (c Config) ImageOverride(impl NodeImpl) string {
	if impl == ImplPluto {
		return c.ImplImage(impl)
	}

	return ""
}

// UsesPluto returns true if any node or keygen step runs pluto.
func (c Config) UsesPluto() bool {
	if c.KeygenImpl() == ImplPluto {
		return true
	}

	for i := range c.NumNodes {
		if c.NodeImpl(i) == ImplPluto {
			return true
		}
	}

	return false
}

// NewDefaultConfig returns a new default config.
func NewDefaultConfig() Config {
	return Config{
		Version:                 version,
		NumNodes:                defaultNumNodes,
		Threshold:               defaultThreshold,
		NumValidators:           defaultNumVals,
		ImageTag:                defaultImageTag,
		NodeImpls:               []NodeImpl{ImplCharon},
		PlutoImageTag:           "local",
		VCs:                     []VCType{VCLighthouse, VCLighthouse, VCMock},
		KeyGen:                  defaultKeyGen,
		BeaconNodes:             defaultBeaconNode,
		Step:                    stepNew,
		FeatureSet:              defaultFeatureSet,
		SlotDuration:            time.Second,
		SyntheticBlockProposals: true,
		Monitoring:              true,
	}
}
