// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/enr"
)

// zeroAddress is not owned by any user, is often associated with token burn & mint/genesis events and used as a generic null address.
// See https://etherscan.io/address/0x0000000000000000000000000000000000000000.
const zeroAddress = `"0x0000000000000000000000000000000000000000"`

// Clean deletes all compose directory files and artifacts.
func Clean(ctx context.Context, dir string) error {
	ctx = log.WithTopic(ctx, "clean")

	files, err := filepath.Glob(path.Join(dir, "*"))
	if err != nil {
		return errors.Wrap(err, "glob dir")
	}

	// Make sure we ONLY delete compose artifacts.
	var (
		configFound bool
		goFound     bool
	)

	for _, file := range files {
		if file == configFile {
			configFound = true
		} else if strings.HasSuffix(file, ".go") || strings.HasPrefix(file, "go.") {
			goFound = true
		}
	}

	if !configFound {
		log.Info(ctx, "Not cleaning since config.json not found")
		return nil
	} else if goFound {
		return errors.New("go files found, compose dir incorrect", z.Str("dir", dir))
	}

	log.Info(ctx, "Cleaning compose dir", z.Int("files", len(files)))

	for _, file := range files {
		if strings.Contains(file, "key") {
			// Do not delete root folder with key in the name, since it might be long-lived split keys folder.
			log.Info(ctx, "Not deleting *key* folder", z.Str("path", file))
			continue
		}

		if err := os.RemoveAll(file); err != nil {
			return errors.Wrap(err, "remove file")
		}
	}

	return nil
}

// noPull allows disabling pulling during unit tests.
var noPull bool

// Define defines a compose cluster; including both keygen and running definitions.
func Define(ctx context.Context, dir string, conf Config) (TmplData, error) {
	if conf.Step != stepNew {
		return TmplData{}, errors.New("compose config not new, so can't be defined", z.Any("step", conf.Step))
	}

	if conf.BuildLocal {
		if err := BuildLocal(ctx); err != nil {
			return TmplData{}, err
		}
	}

	if !noPull && !conf.BuildLocal && conf.ImageTag == "latest" {
		if err := pullLatest(ctx); err != nil {
			return TmplData{}, err
		}
	}

	if !noPull && conf.UsesPluto() && conf.PlutoImageTag == "local" {
		if err := BuildLocalPluto(ctx); err != nil {
			return TmplData{}, err
		}
	}

	if conf.SplitKeysDir != "" {
		if err := validateSplitKeysDir(dir, conf.SplitKeysDir); err != nil {
			return TmplData{}, err
		}
	}

	var data TmplData

	if conf.KeyGen == KeyGenDKG {
		log.Info(ctx, "Creating node*/charon-enr-private-key for ENRs required for charon create dkg")

		// charon create dkg requires operator ENRs, so we need to create p2pkeys now.
		p2pkeys, err := newP2PKeys(conf.NumNodes)
		if err != nil {
			return TmplData{}, err
		}

		var enrs []string

		for i, key := range p2pkeys {
			// Best effort creation of folder, rather fail when saving p2pkey file next.
			_ = os.MkdirAll(nodeFile(dir, i, ""), 0o755)

			err := k1util.Save(key, nodeFile(dir, i, "charon-enr-private-key"))
			if err != nil {
				return TmplData{}, errors.Wrap(err, "save charon-enr-private-key")
			}

			record, err := enr.New(key)
			if err != nil {
				return TmplData{}, err
			}

			enrs = append(enrs, record.String())
		}

		kvs := []kv{
			{"name", "compose"},
			{"num_validators", strconv.Itoa(conf.NumValidators)},
			{"operator_enrs", strings.Join(enrs, ",")},
			{"threshold", strconv.Itoa(conf.Threshold)},
			{"withdrawal_addresses", zeroAddress},
			{"fee-recipient_addresses", zeroAddress},
			{"dkg_algorithm", "frost"},
			{"output_dir", "/compose"},
			{"network", eth2util.Goerli.Name},
		}

		n := TmplNode{Image: conf.ImageOverride(conf.KeygenImpl()), EnvVars: kvs}

		data = TmplData{
			ComposeDir:     dir,
			CharonImageTag: conf.ImageTag,
			CharonCommand:  cmdCreateDKG,
			Nodes:          []TmplNode{n},
		}
	} else {
		// Other keygens only need a noop docker compose, since charon-compose.yml
		// is used directly in their compose lock.
		data = TmplData{
			ComposeDir:       dir,
			CharonImageTag:   conf.ImageTag,
			CharonEntrypoint: "echo",
			CharonCommand:    fmt.Sprintf("No charon commands needed for keygen=%s define step", conf.KeyGen),
			Nodes:            []TmplNode{{}},
		}
	}

	log.Info(ctx, "Creating config.json")

	conf.Step = stepDefined
	if err := WriteConfig(dir, conf); err != nil {
		return TmplData{}, err
	}

	if err := copyStaticFolders(dir); err != nil {
		return TmplData{}, err
	}

	if err := writePrometheusConfig(dir, conf); err != nil {
		return TmplData{}, err
	}

	if err := writeAlertRules(dir, conf); err != nil {
		return TmplData{}, err
	}

	log.Info(ctx, "Creating docker-compose.yml")
	log.Info(ctx, "Create cluster definition: docker compose up")

	if err := WriteDockerCompose(dir, data); err != nil {
		return TmplData{}, err
	}

	return data, nil
}

// validateSplitKeysDir returns an error if the split keys dir is not a child of dir.
func validateSplitKeysDir(dir string, spitKeysDir string) error {
	rel, err := getRelSplitKeysDir(dir, spitKeysDir)
	if err != nil {
		return err
	} else if strings.HasPrefix(rel, "..") {
		return errors.New("split-keys-dir must be a child of compose dir", z.Str("relative", rel))
	}

	return nil
}

// getRelSplitKeysDir returns the splitKeysDir as a relative path to dir.
func getRelSplitKeysDir(dir, splitKeysDir string) (string, error) {
	if splitKeysDir == "" {
		return "", nil
	}

	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", errors.Wrap(err, "abs dir")
	}

	splitKeysDir, err = filepath.Abs(splitKeysDir)
	if err != nil {
		return "", errors.Wrap(err, "abs dir")
	}

	rel, err := filepath.Rel(dir, splitKeysDir)
	if err != nil {
		return "", errors.Wrap(err, "relative split keys dir")
	}

	return rel, nil
}

// pullLatest pulls the latest charon docker image.
func pullLatest(ctx context.Context) error {
	log.Info(ctx, "Pulling latest charon docker image")

	cmd := exec.CommandContext(ctx, "docker", "pull", charonImage+":latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "run docker pull")
	}

	return nil
}

// BuildLocal builds an `obolnetwork/charon:local` docker container from source. Note this requires CHARON_REPO env var.
func BuildLocal(ctx context.Context) error {
	repo, ok := os.LookupEnv("CHARON_REPO")
	if !ok || repo == "" {
		return errors.New("cannot build local charon binary; CHARON_REPO env var, the path to the charon repo, is not set")
	}

	log.Info(ctx, "Building `obolnetwork/charon:local` docker container", z.Str("repo", repo))

	var out bytes.Buffer // Only log output if there is an error.

	cmd := exec.CommandContext(ctx, "docker", "build", "-t", "obolnetwork/charon:local", ".")
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Dir = repo

	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "exec docker build", z.Str("output", out.String()))
	}

	return nil
}

// BuildLocalPluto builds a `pluto:local` docker container from source. Note this requires PLUTO_REPO env var.
func BuildLocalPluto(ctx context.Context) error {
	repo, ok := os.LookupEnv("PLUTO_REPO")
	if !ok || repo == "" {
		return errors.New("cannot build local pluto binary; PLUTO_REPO env var, the path to the pluto repo, is not set")
	}

	log.Info(ctx, "Building `pluto:local` docker container", z.Str("repo", repo))

	args := []string{"build", "-t", "pluto:local"}

	// Bake the git hash into the image: peers exchange it over peerinfo and
	// warn about an empty/unparseable hash ("Invalid peer git hash").
	if hash, err := gitCommitHashShort(ctx, repo); err == nil {
		args = append(args, "--build-arg", "GIT_COMMIT_HASH_SHORT="+hash)
	}

	args = append(args, ".")

	var out bytes.Buffer // Only log output if there is an error.

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Dir = repo

	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "exec docker build", z.Str("output", out.String()))
	}

	return nil
}

// gitCommitHashShort returns the repo's short (7 char) commit hash.
func gitCommitHashShort(ctx context.Context, repo string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--short=7", "HEAD")
	cmd.Dir = repo

	out, err := cmd.Output()
	if err != nil {
		return "", errors.Wrap(err, "git rev-parse")
	}

	return strings.TrimSpace(string(out)), nil
}

// copyStaticFolders copies the embedded static folders to the compose dir.
func copyStaticFolders(dir string) error {
	const staticRoot = "static"

	dirs, err := static.ReadDir(staticRoot)
	if err != nil {
		return errors.Wrap(err, "read dirs")
	}

	for _, d := range dirs {
		if !d.IsDir() {
			return errors.New("static files not supported")
		}

		if err := os.MkdirAll(path.Join(dir, d.Name()), 0o755); err != nil {
			return errors.Wrap(err, "mkdir all")
		}

		files, err := static.ReadDir(path.Join(staticRoot, d.Name()))
		if err != nil {
			return errors.Wrap(err, "read files")
		}

		for _, f := range files {
			if f.IsDir() {
				return errors.New("child static dirs not supported")
			}

			b, err := static.ReadFile(path.Join(staticRoot, d.Name(), f.Name()))
			if err != nil {
				return errors.Wrap(err, "read file")
			}

			var mode os.FileMode = 0o644
			if strings.HasSuffix(f.Name(), ".sh") {
				mode = 0o755
			}

			if err := os.WriteFile(path.Join(dir, d.Name(), f.Name()), b, mode); err != nil {
				return errors.Wrap(err, "write file")
			}
		}
	}

	return nil
}

// writePrometheusConfig writes prometheus scrape configs for the actual
// cluster size, replacing the static 4-node default copied from static/.
// Unlike charon's static config, this scrapes the relay (not a non-existent
// "bootnode") and covers all NumNodes so the `up == 0` alert works.
func writePrometheusConfig(dir string, conf Config) error {
	var b strings.Builder

	b.WriteString(`global:
  scrape_interval:     5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: 'relay'
    static_configs:
      - targets: [ 'relay:3620' ]
`)

	for i := range conf.NumNodes {
		fmt.Fprintf(&b, `  - job_name: 'node%d'
    static_configs:
      - targets: ['node%d:3620']
`, i, i)
	}

	b.WriteString(`
rule_files:
  - /etc/prometheus/rules.yml
`)

	if err := os.MkdirAll(path.Join(dir, "prometheus"), 0o755); err != nil {
		return errors.Wrap(err, "mkdir prometheus")
	}

	err := os.WriteFile(path.Join(dir, "prometheus", "prometheus.yml"), []byte(b.String()), 0o644) //nolint:gosec
	if err != nil {
		return errors.Wrap(err, "write prometheus.yml")
	}

	return nil
}

// Canonical alert rule names: generated by writeAlertRules, validated
// against Config.AlertDisableRules, and referenced by the alert collector's
// warmup allowlist.
const (
	plutoDownRule = "Pluto Down"
	errorRateRule = "Error Log Rate"
	warnRateRule  = "Warn Log Rate"
	vapiRateRule  = "Validator API Error Rate"
	proxyRateRule = "Proxy API Error Rate"
	broadcastRule = "Broadcast Duty Rate"
)

// alertRuleNames is the set of valid rule names for Config.AlertDisableRules.
var alertRuleNames = map[string]bool{
	plutoDownRule: true,
	errorRateRule: true,
	warnRateRule:  true,
	vapiRateRule:  true,
	proxyRateRule: true,
	broadcastRule: true,
}

// writeAlertRules writes the prometheus alert rules evaluated by the smoke
// tests. Rules are generated (not static) because the expressions depend on
// config: scenarios that deliberately degrade a node exempt its job via
// conf.AlertExcludeJobs, mixed-impl scenarios extend the warn-topic
// exclusions via conf.AlertWarnExcludeTopics, and cluster-wide degradations
// drop whole rules via conf.AlertDisableRules.
//
// Charon's "Outstanding Duty Rate" rule (core_bcast_broadcast_total -
// core_scheduler_duty_total > 50) is deliberately not ported: a node cannot
// broadcast a duty more often than it is scheduled, and the two counters
// only share a subset of duty label values (the rest drop out of the vector
// match), so the expression can never exceed zero — the rule is dead
// upstream too.
func writeAlertRules(dir string, conf Config) error {
	// Exclusion matcher for per-node behavioral rules; empty when no node is
	// exempted. "Pluto Down" (up == 0) is never exempted: a degraded node
	// must still be scrapable.
	var jobExcl string
	if len(conf.AlertExcludeJobs) > 0 {
		jobExcl = fmt.Sprintf(`job!~"%s"`, strings.Join(conf.AlertExcludeJobs, "|"))
	}

	// sel renders a PromQL label-matcher block from the non-empty matchers.
	sel := func(matchers ...string) string {
		var parts []string
		for _, m := range matchers {
			if m != "" {
				parts = append(parts, m)
			}
		}

		if len(parts) == 0 {
			return ""
		}

		return "{" + strings.Join(parts, ",") + "}"
	}

	// Warn Log Rate always excludes charon v1.7.1 topics that warn
	// structurally in any healthy simnet cluster (verified in the all-charon
	// `dkg` scenario):
	//  - vmock: the in-process validatormock schedules DutyBuilderRegistration
	//    every epoch (~16 duties per epoch start) with no handler, so every
	//    VCMock node warns "Duty failed: unexpected duty" in bursts.
	//  - tracker: the beaconmock never includes broadcast duties on-chain, so
	//    every successful proposal epoch warns "Broadcasted block/attestation
	//    never included on-chain" (the better the cluster works, the more it
	//    warns).
	// Both are mock artifacts, not node behavior; all other warn topics stay
	// gated unless a scenario opts out via AlertWarnExcludeTopics.
	warnTopics := strings.Join(append([]string{"vmock", "tracker"}, conf.AlertWarnExcludeTopics...), "|")

	// The broadcast-liveness expression must fail when a node exposes NO
	// core_bcast_broadcast_total series at all: the counter is created on
	// first broadcast, so a node that never broadcasts has no series and a
	// plain `increase(...) < 0.5` can never fire for it. Inject a 0 for
	// every scraped node job (`0 * up`) so absent series alert too. Summed
	// per job because the per-duty sync_message series legitimately pauses 6
	// of every 8 epochs (simnet sync-committee membership window). Scoped to
	// node jobs: the relay never broadcasts duties.
	bcastSel := sel(`job=~"node[0-9]+"`, jobExcl)

	errorSel := sel(jobExcl)
	warnSel := sel(fmt.Sprintf(`topic!~"%s"`, warnTopics), jobExcl)
	vapiSel := sel(`endpoint!="proxy"`, jobExcl)
	proxySel := sel(`endpoint="proxy"`, jobExcl)

	// Blocks keyed by rule name so conf.AlertDisableRules can drop whole
	// rules; the names double as the collector's warmup allowlist keys.
	ruleBlocks := []struct {
		name  string
		block string
	}{
		{plutoDownRule, `  - alert: Pluto Down
    expr: up == 0
    for: 15s
    annotations:
      description: "Pluto {{ $labels.job }} is down"
`},
		// Windowed instead of charon's absolute app_log_error_total > 0: a
		// fresh simnet cluster loses the first epoch-boundary proposer
		// consensus (vmock 2-slot startup delay -> no randao yet), logging
		// exactly one consensus timeout ERROR per node on charon and pluto
		// alike. An absolute counter gate can never recover from that
		// cold-start artifact; a 30s window plus the collector warmup
		// (compose/alert.go) gates steady-state errors only.
		{errorRateRule, fmt.Sprintf(`  - alert: Error Log Rate
    expr: increase(app_log_error_total%s[30s]) > 0
    for: 15s
    annotations:
      description: "Pluto {{ $labels.job }} has a high error rate"
`, errorSel)},
		{warnRateRule, fmt.Sprintf(`  - alert: Warn Log Rate
    expr: increase(app_log_warn_total%s[30s]) > 2
    for: 15s
    annotations:
      description: "Pluto {{ $labels.job }} has a high warning rate"
`, warnSel)},
		{vapiRateRule, fmt.Sprintf(`  - alert: Validator API Error Rate
    expr: increase(core_validatorapi_request_error_total%s[30s]) > 1
    for: 15s
    annotations:
      description: "Pluto {{ $labels.job }} validator API a high error rate"
`, vapiSel)},
		{proxyRateRule, fmt.Sprintf(`  - alert: Proxy API Error Rate
    expr: increase(core_validatorapi_request_error_total%s[30s]) > 5
    for: 15s
    annotations:
      description: "Pluto {{ $labels.job }} proxy API a high error rate"
`, proxySel)},
		{broadcastRule, fmt.Sprintf(`  - alert: Broadcast Duty Rate
    expr: (sum by (job) (increase(core_bcast_broadcast_total%[1]s[30s])) or on (job) max by (job) (0 * up%[1]s)) < 0.5
    for: 15s
    annotations:
      description: "Pluto {{ $labels.job }} is not broadcasting enough duties"
`, bcastSel)},
	}

	disabled := make(map[string]bool)
	for _, rule := range conf.AlertDisableRules {
		disabled[rule] = true
	}

	var b strings.Builder

	b.WriteString("groups:\n- name: pluto\n  rules:\n")

	for _, rule := range ruleBlocks {
		if disabled[rule.name] {
			continue
		}

		b.WriteString(rule.block)
		b.WriteString("\n")
	}

	rules := strings.TrimSuffix(b.String(), "\n")

	if err := os.MkdirAll(path.Join(dir, "prometheus"), 0o755); err != nil {
		return errors.Wrap(err, "mkdir prometheus")
	}

	err := os.WriteFile(path.Join(dir, "prometheus", "rules.yml"), []byte(rules), 0o644) //nolint:gosec
	if err != nil {
		return errors.Wrap(err, "write rules.yml")
	}

	return nil
}

// keyGenFunc can be overridden in tests for deterministic p2pkeys.
var keyGenFunc = func() (*k1.PrivateKey, error) {
	privkey, err := k1.GeneratePrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "new priv key")
	}

	return privkey, nil
}

// newP2PKeys returns a slice of newly generated secp256k1 private keys.
func newP2PKeys(n int) ([]*k1.PrivateKey, error) {
	var resp []*k1.PrivateKey

	for range n {
		key, err := keyGenFunc()
		if err != nil {
			return nil, errors.Wrap(err, "new key")
		}

		resp = append(resp, key)
	}

	return resp, nil
}

// nodeFile returns the path to a file in a node folder.
func nodeFile(dir string, i int, file string) string {
	return path.Join(dir, fmt.Sprintf("node%d", i), file)
}

// WriteConfig writes the config as yaml to disk.
func WriteConfig(dir string, conf Config) error {
	if err := conf.Validate(); err != nil {
		return err
	}

	b, err := json.MarshalIndent(conf, "", " ")
	if err != nil {
		return errors.Wrap(err, "marshal config")
	}

	err = os.WriteFile(path.Join(dir, configFile), b, 0o755) //nolint:gosec
	if err != nil {
		return errors.Wrap(err, "write config")
	}

	return nil
}
