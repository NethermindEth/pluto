// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

import (
	"os"
	"path"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWritePrometheusConfigScrapesAllNodes asserts the generated scrape
// config covers every configured node plus the relay, so the `up == 0` and
// injected-zero broadcast alerts can see all of them.
func TestWritePrometheusConfigScrapesAllNodes(t *testing.T) {
	dir := t.TempDir()

	conf := NewDefaultConfig()
	conf.NumNodes = 10

	require.NoError(t, writePrometheusConfig(dir, conf))

	b, err := os.ReadFile(path.Join(dir, "prometheus", "prometheus.yml"))
	require.NoError(t, err)

	content := string(b)
	require.Contains(t, content, "- targets: [ 'relay:3620' ]")

	for i := range conf.NumNodes {
		require.Contains(t, content, "job_name: 'node"+strconv.Itoa(i)+"'")
		require.Contains(t, content, "- targets: ['node"+strconv.Itoa(i)+":3620']")
	}

	require.NotContains(t, content, "node10", "must not scrape beyond NumNodes")
}

// TestWriteAlertRulesBroadcastCoversMissingSeries asserts the broadcast
// liveness expression injects a zero for scraped node jobs with no
// core_bcast_broadcast_total series, so a node that never broadcasts (the
// counter is only created on first broadcast) fails instead of silently
// passing.
func TestWriteAlertRulesBroadcastCoversMissingSeries(t *testing.T) {
	content := writeRules(t, NewDefaultConfig())

	require.Contains(t, content,
		`expr: (sum by (job) (increase(core_bcast_broadcast_total{job=~"node[0-9]+"}[30s])) or on (job) max by (job) (0 * up{job=~"node[0-9]+"})) < 0.5`)
}

// TestWriteAlertRulesExcludesDegradedJobs asserts AlertExcludeJobs exempts a
// node from every behavioral rule while "Pluto Down" keeps watching it.
func TestWriteAlertRulesExcludesDegradedJobs(t *testing.T) {
	conf := NewDefaultConfig()
	conf.AlertExcludeJobs = []string{"node0"}

	content := writeRules(t, conf)

	require.Contains(t, content, `increase(app_log_error_total{job!~"node0"}[30s]) > 0`)
	require.Contains(t, content, `increase(app_log_warn_total{topic!~"vmock|tracker",job!~"node0"}[30s]) > 2`)
	require.Contains(t, content, `increase(core_validatorapi_request_error_total{endpoint!="proxy",job!~"node0"}[30s]) > 1`)
	require.Contains(t, content, `increase(core_validatorapi_request_error_total{endpoint="proxy",job!~"node0"}[30s]) > 5`)
	require.Contains(t, content,
		`(sum by (job) (increase(core_bcast_broadcast_total{job=~"node[0-9]+",job!~"node0"}[30s])) or on (job) max by (job) (0 * up{job=~"node[0-9]+",job!~"node0"})) < 0.5`)

	// The scrape-liveness rule must never carry exclusions.
	require.Contains(t, content, "expr: up == 0")
}

// TestWriteAlertRulesWarnTopicExtension asserts scenario-scoped warn-topic
// exclusions append to the built-in mock-noise list.
func TestWriteAlertRulesWarnTopicExtension(t *testing.T) {
	conf := NewDefaultConfig()
	conf.AlertWarnExcludeTopics = []string{"sched"}

	content := writeRules(t, conf)
	require.Contains(t, content, `increase(app_log_warn_total{topic!~"vmock|tracker|sched"}[30s]) > 2`)
}

// TestWriteAlertRulesDropsOutstandingDuty pins the removal of charon's dead
// "Outstanding Duty Rate" rule (broadcast counts can never exceed scheduled
// counts, so the expression could never fire).
func TestWriteAlertRulesDropsOutstandingDuty(t *testing.T) {
	content := writeRules(t, NewDefaultConfig())
	require.NotContains(t, content, "Outstanding Duty")
	require.NotContains(t, content, "core_scheduler_duty_total")
}

// TestWriteAlertRulesDisableRules asserts AlertDisableRules drops exactly the
// named rules and validation rejects unknown names.
func TestWriteAlertRulesDisableRules(t *testing.T) {
	conf := NewDefaultConfig()
	conf.AlertDisableRules = []string{"Error Log Rate", "Validator API Error Rate"}

	content := writeRules(t, conf)
	require.NotContains(t, content, "Error Log Rate")
	require.NotContains(t, content, `endpoint!="proxy"`)
	// The remaining gates stay.
	require.Contains(t, content, "Pluto Down")
	require.Contains(t, content, "Warn Log Rate")
	require.Contains(t, content, "Proxy API Error Rate")
	require.Contains(t, content, "Broadcast Duty Rate")

	conf = NewDefaultConfig()
	conf.AlertDisableRules = []string{"No Such Rule"}
	require.ErrorContains(t, WriteConfig(t.TempDir(), conf), "unknown alert rule name")
}

// TestConfigValidateRejectsUnknownImpl asserts unknown implementation names
// fail on write and on load instead of silently running the charon image.
func TestConfigValidateRejectsUnknownImpl(t *testing.T) {
	conf := NewDefaultConfig()
	conf.NodeImpls = []NodeImpl{ImplCharon, "geth"}
	require.ErrorContains(t, WriteConfig(t.TempDir(), conf), "unknown node implementation")

	conf = NewDefaultConfig()
	conf.KeyGenImpl = "plutoo"
	require.ErrorContains(t, WriteConfig(t.TempDir(), conf), "unknown keygen implementation")

	// Loading a hand-edited config with a bad impl fails too.
	dir := t.TempDir()
	badJSON := `{"version":"obol/charon/compose/1.0.0","node_impls":["geth"]}`
	require.NoError(t, os.WriteFile(path.Join(dir, "config.json"), []byte(badJSON), 0o644))
	_, err := LoadConfig(dir)
	require.ErrorContains(t, err, "unknown node implementation")

	// The happy path still validates.
	conf = NewDefaultConfig()
	conf.NodeImpls = []NodeImpl{ImplCharon, ImplPluto}
	conf.KeyGenImpl = ImplPluto
	dir = t.TempDir()
	require.NoError(t, WriteConfig(dir, conf))
	_, err = LoadConfig(dir)
	require.NoError(t, err)
}

// writeRules writes alert rules for conf into a temp dir and returns them.
func writeRules(t *testing.T, conf Config) string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, writeAlertRules(dir, conf))

	b, err := os.ReadFile(path.Join(dir, "prometheus", "rules.yml"))
	require.NoError(t, err)

	return string(b)
}
