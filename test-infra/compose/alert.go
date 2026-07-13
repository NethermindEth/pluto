// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const alertsPolled = "alerts_polled"

// alertWarmup is the window after Prometheus first answers the rules API in
// which the known cold-start transients (startupTransientRules) may fire; they
// must resolve before it ends. Alerts outside that allowlist fail immediately,
// warmup or not. Callers must give the alert context comfortably more than
// this (the smoke suite uses 2m timeouts).
const alertWarmup = time.Second * 60

// startupTransientRules names the alert rules that fire on any healthy
// cluster while it boots and self-resolve within the warmup window (all rule
// expressions are windowed, so a transient ages out):
//   - Error Log Rate: the first epoch-boundary proposer consensus fails on
//     every node (the validatormock delays 2 slots before submitting duties,
//     so no randao exists yet), logging one consensus-timeout ERROR each.
//   - Warn Log Rate: charon's app-start warning burst (insecure relay URL,
//     empty QUIC address, beacon version parse) exceeds the 30s-window
//     threshold once at boot.
//   - Broadcast Duty Rate: nodes are scraped before the p2p mesh forms and
//     the first duties broadcast, so the injected absent-series zero fires.
//
// Anything else firing during warmup (e.g. Pluto Down, validator API error
// rates) is a real failure and is reported immediately.
var startupTransientRules = map[string]bool{
	errorRateRule: true,
	warnRateRule:  true,
	broadcastRule: true,
}

// activeAlert is a firing alert: the rule name that produced it and its
// rendered description.
type activeAlert struct {
	Rule        string
	Description string
}

// startAlertCollector starts a goroutine that polls prometheus alerts until the context is closed and returns
// a channel on which the received alert descriptions will be sent.
func startAlertCollector(ctx context.Context, dir string) chan string {
	resp := make(chan string, 100)

	go func() {
		defer close(resp)

		const iterSleep = time.Second * 2

		// Wait for Prometheus to answer instead of sleeping blindly; the
		// warmup window is anchored to readiness so slow container starts do
		// not eat into it.
		readyAt, ok := awaitPrometheusReady(ctx, dir, iterSleep)
		if !ok {
			return // Context closed: Auto reports "alerts couldn't be polled".
		}

		log.Info(ctx, "Prometheus ready, collecting alerts",
			z.Str("warmup", alertWarmup.String()))

		resp <- alertsPolled // Push initial "fake alert" so logic can fail if no alerts polled.

		warmupEnd := readyAt.Add(alertWarmup)

		var (
			reported = make(map[string]bool)
			ignored  = make(map[string]bool)
		)

		for ; ctx.Err() == nil; time.Sleep(iterSleep) { // Sleep for iterSleep before next iteration.
			alerts, err := queryAlerts(ctx, dir)
			if ctx.Err() != nil {
				return
			} else if err != nil {
				log.Error(ctx, "Poll prometheus alerts", err)
				continue
			}

			if alerts.Status != "success" {
				resp <- "non success status from prometheus alerts: " + alerts.Status
				continue
			}

			inWarmup := time.Now().Before(warmupEnd)

			for _, active := range getActiveAlerts(alerts) {
				if inWarmup && startupTransientRules[active.Rule] {
					if !ignored[active.Description] {
						ignored[active.Description] = true
						log.Info(ctx, "Ignoring known cold-start transient during warmup",
							z.Str("alert", active.Description))
					}

					continue // Still fails if firing after warmup, see below.
				}

				if reported[active.Description] {
					continue
				}

				reported[active.Description] = true
				log.Info(ctx, "Detected new alert", z.Str("alert", active.Description))

				resp <- active.Description
			}
		}
	}()

	return resp
}

// awaitPrometheusReady polls the prometheus rules API until it answers
// successfully, returning the readiness time. Returns false if the context
// closes first.
func awaitPrometheusReady(ctx context.Context, dir string, interval time.Duration) (time.Time, bool) {
	log.Info(ctx, "Waiting for prometheus to answer the rules API")

	for ctx.Err() == nil {
		alerts, err := queryAlerts(ctx, dir)
		if err == nil && alerts.Status == "success" {
			return time.Now(), true
		}

		time.Sleep(interval)
	}

	return time.Time{}, false
}

// queryAlerts fetches and parses the prometheus alert rules via the curl
// container.
func queryAlerts(ctx context.Context, dir string) (promAlerts, error) {
	//nolint:revive // tls not required for testing.
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "curl", "curl", "-s", "http://prometheus:9090/api/v1/rules?type=alert")
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		return promAlerts{}, errors.Wrap(err, "exec curl alerts", z.Str("out", string(out)))
	}

	var alerts promAlerts
	if err := json.Unmarshal(bytes.TrimSpace(out), &alerts); err != nil {
		return promAlerts{}, errors.Wrap(err, "unmarshal alerts", z.Str("out", string(out)))
	}

	return alerts, nil
}

func getActiveAlerts(alerts promAlerts) []activeAlert {
	var resp []activeAlert

	for _, group := range alerts.Data.Groups {
		for _, rule := range group.Rules {
			for _, alert := range rule.Alerts {
				// Prometheus reports alert states as inactive/pending/firing.
				// Charon matches "active" here, which never occurs, so its
				// alert gate silently passes everything (upstream bug).
				if alert.State != "firing" {
					continue
				}

				resp = append(resp, activeAlert{
					Rule:        rule.Name,
					Description: alert.Annotations.Description,
				})
			}
		}
	}

	return resp
}

// promAlerts is the json response returned by querying prometheus alerts.
type promAlerts struct {
	Status string `json:"status"`
	Data   struct {
		Groups []struct {
			Name  string `json:"name"`
			Rules []struct {
				Name   string `json:"name"`
				Alerts []struct {
					State       string `json:"state"`
					Annotations struct {
						Description string `json:"description"`
					} `json:"annotations"`
				} `json:"alerts"`
			} `json:"rules"`
		} `json:"groups"`
	} `json:"data"`
}
