package harness

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
)

// PlutoBin returns the pluto binary path from $PLUTO_BIN, or empty if unset.
func PlutoBin() string {
	return os.Getenv("PLUTO_BIN")
}

// PlutoSupportsRun reports whether the pluto binary exposes a `run` command.
// Scenarios involving pluto nodes are skipped until it lands.
func PlutoSupportsRun(bin string) bool {
	if bin == "" {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return exec.CommandContext(ctx, bin, "run", "--help").Run() == nil
}

// SkipUnlessPluto skips the test unless $PLUTO_BIN is set and supports
// `pluto run`, returning the binary path otherwise.
func SkipUnlessPluto(t *testing.T) string {
	t.Helper()

	bin := PlutoBin()
	if bin == "" {
		t.Skip("PLUTO_BIN not set; skipping pluto simnet scenario")
	}

	if !PlutoSupportsRun(bin) {
		t.Skip("pluto binary does not support `run` yet; skipping pluto simnet scenario")
	}

	return bin
}

// StartPlutoRelay launches `pluto relay` as a subprocess and returns its HTTP
// ENR endpoint (the same `http://host:port` form charon's relay exposes), for
// use as a `--p2p-relays` value by both pluto and charon nodes.
//
// `--p2p-advertise-private-addresses` is required: the relay binds loopback in
// the harness, and without advertising private addresses the circuit
// reservations it issues carry no address, which rust-libp2p relay clients
// reject with `NoAddressesInReservation`.
func StartPlutoRelay(t *testing.T, ctx context.Context, bin string) string {
	t.Helper()

	dir := t.TempDir()
	httpAddr := testutil.AvailableAddr(t).String()

	args := []string{
		"relay",
		"--data-dir=" + dir,
		"--http-address=" + httpAddr,
		"--p2p-tcp-address=" + testutil.AvailableAddr(t).String(),
		"--p2p-advertise-private-addresses",
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	cmd.Stderr = cmd.Stdout

	go logLines(t, "pluto[relay]", stdout)

	require.NoError(t, cmd.Start(), "start pluto relay")

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Wait for the ENR HTTP endpoint to accept connections before returning.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		conn, err := net.DialTimeout("tcp", httpAddr, time.Second)
		if err == nil {
			_ = conn.Close()
			return "http://" + httpAddr
		}

		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("pluto relay HTTP endpoint %s not ready", httpAddr)

	return ""
}

// PlutoNode is a pluto node running as a subprocess of the pluto binary.
type PlutoNode struct {
	Idx      int
	Dir      string
	VAPIAddr string
}

// StartPlutoNode writes node i's on-disk fixture and launches
// `pluto run` against the given beacon gateway and relay. The node flags
// mirror `charon run` flags for functional equivalence.
func StartPlutoNode(
	t *testing.T,
	ctx context.Context,
	fixture *Fixture,
	peerIdx int,
	bin, relayAddr, gatewayAddr string,
) *PlutoNode {
	t.Helper()

	dir := fixture.WriteNodeDir(t, peerIdx)

	args := []string{
		"run",
		"--lock-file=" + dir + "/cluster-lock.json",
		"--private-key-file=" + dir + "/charon-enr-private-key",
		"--beacon-node-endpoints=" + gatewayAddr,
		"--validator-api-address=" + fixture.VAPIAddrs[peerIdx],
		"--monitoring-address=" + testutil.AvailableAddr(t).String(),
		"--p2p-tcp-address=" + testutil.AvailableAddr(t).String(),
		"--p2p-relays=" + relayAddr,
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	cmd.Stderr = cmd.Stdout // interleave; both go to the test log

	go logLines(t, fmt.Sprintf("pluto[node%d]", peerIdx), stdout)

	require.NoError(t, cmd.Start(), "start pluto node %d", peerIdx)

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	return &PlutoNode{Idx: peerIdx, Dir: dir, VAPIAddr: fixture.VAPIAddrs[peerIdx]}
}

// WaitReady blocks until the node's validator API accepts TCP connections.
func (n *PlutoNode) WaitReady(t *testing.T, ctx context.Context, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		conn, err := net.DialTimeout("tcp", n.VAPIAddr, time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}

		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("pluto node %d validator API %s not ready after %s", n.Idx, n.VAPIAddr, timeout)
}

// logLines forwards subprocess output to the test log with a prefix.
func logLines(t *testing.T, prefix string, r interface{ Read([]byte) (int, error) }) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		t.Logf("%s: %s", prefix, scanner.Text())
	}
}
