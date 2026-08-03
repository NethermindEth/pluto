// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGetActiveAlertsFiringOnly asserts only firing alerts are reported:
// pending and inactive states (and charon's never-occurring "active") are
// ignored.
func TestGetActiveAlertsFiringOnly(t *testing.T) {
	payload := `{
		"status": "success",
		"data": {
			"groups": [
				{
					"name": "pluto",
					"rules": [
						{
							"name": "Error Log Rate",
							"alerts": [
								{"state": "firing", "annotations": {"description": "node0 has a high error rate"}},
								{"state": "pending", "annotations": {"description": "node1 has a high error rate"}}
							]
						},
						{
							"name": "Pluto Down",
							"alerts": [
								{"state": "inactive", "annotations": {"description": "node2 is down"}},
								{"state": "active", "annotations": {"description": "node3 is down"}}
							]
						}
					]
				}
			]
		}
	}`

	var alerts promAlerts
	require.NoError(t, json.Unmarshal([]byte(payload), &alerts))

	active := getActiveAlerts(alerts)
	require.Equal(t, []activeAlert{{
		Rule:        "Error Log Rate",
		Description: "node0 has a high error rate",
	}}, active)
}

// TestStartupTransientRulesScoped pins the warmup allowlist: only the three
// proven cold-start transients may fire during warmup; scrape and API error
// alerts always fail.
func TestStartupTransientRulesScoped(t *testing.T) {
	require.True(t, startupTransientRules["Error Log Rate"])
	require.True(t, startupTransientRules["Warn Log Rate"])
	require.True(t, startupTransientRules["Broadcast Duty Rate"])

	require.False(t, startupTransientRules["Pluto Down"])
	require.False(t, startupTransientRules["Validator API Error Rate"])
	require.False(t, startupTransientRules["Proxy API Error Rate"])
	require.Len(t, startupTransientRules, 3)
}
