package perfbench

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/obolnetwork/charon/core/qbft"
)

// Mirrors the Rust tier2 QBFT bench: N in-process participants, i64 values,
// never-firing round timers, blocking fan-out broadcast, value 42, measured
// from spawn to all processes deciding.

const (
	qbftInstance  = int64(1)
	qbftValue     = int64(42)
	qbftFIFOLimit = 100
)

type benchMsg struct {
	typ     qbft.MsgType
	inst    int64
	source  int64
	round   int64
	value   int64
	pr      int64
	pv      int64
	justify []qbft.Msg[int64, int64, int64]
}

var _ qbft.Msg[int64, int64, int64] = benchMsg{}

func (m benchMsg) Type() qbft.MsgType { return m.typ }

func (m benchMsg) Instance() int64 { return m.inst }

func (m benchMsg) Source() int64 { return m.source }

func (m benchMsg) Round() int64 { return m.round }

func (m benchMsg) Value() int64 { return m.value }

func (m benchMsg) ValueSource() (int64, error) { return m.value, nil }

func (m benchMsg) PreparedRound() int64 { return m.pr }

func (m benchMsg) PreparedValue() int64 { return m.pv }

func (m benchMsg) Justification() []qbft.Msg[int64, int64, int64] { return m.justify }

// runQbftConsensus runs one happy-path consensus instance with n processes
// and returns once every process has decided.
func runQbftConsensus(b *testing.B, n int64) {
	b.Helper()

	// Setup is excluded from timing, matching the Rust bench which times from
	// spawn to all-decided.
	b.StopTimer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	receives := make([]chan qbft.Msg[int64, int64, int64], n)
	for i := range receives {
		receives[i] = make(chan qbft.Msg[int64, int64, int64], 1024)
	}

	decided := make(chan int64, n)

	def := qbft.Definition[int64, int64, int64]{
		IsLeader: func(instance int64, round, process int64) bool {
			return (instance+round)%n == process
		},
		NewTimer: func(round int64) (<-chan time.Time, func()) {
			return make(chan time.Time), func() {}
		},
		Compare: func(_ context.Context, _ qbft.Msg[int64, int64, int64], _ <-chan int64,
			_ int64, returnErr chan error, _ chan int64,
		) {
			returnErr <- nil
		},
		Decide: func(_ context.Context, _ int64, value int64, _ []qbft.Msg[int64, int64, int64]) {
			decided <- value
		},
		LogUponRule: func(context.Context, int64, int64, int64, qbft.Msg[int64, int64, int64], qbft.UponRule) {
		},
		LogRoundChange: func(context.Context, int64, int64, int64, int64, qbft.UponRule, []qbft.Msg[int64, int64, int64]) {
		},
		LogUnjust: func(context.Context, int64, int64, qbft.Msg[int64, int64, int64]) {},
		Nodes:     int(n),
		FIFOLimit: qbftFIFOLimit,
	}

	broadcast := func(ctx context.Context, typ qbft.MsgType, instance int64, source int64,
		round int64, value int64, pr int64, pv int64, justification []qbft.Msg[int64, int64, int64],
	) error {
		msg := benchMsg{
			typ:     typ,
			inst:    instance,
			source:  source,
			round:   round,
			value:   value,
			pr:      pr,
			pv:      pv,
			justify: justification,
		}

		for _, ch := range receives {
			select {
			case ch <- msg:
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		return nil
	}

	var wg sync.WaitGroup

	b.StartTimer()

	for i := int64(1); i <= n; i++ {
		trans := qbft.Transport[int64, int64, int64]{
			Broadcast: broadcast,
			Receive:   receives[i-1],
		}

		wg.Add(1)

		go func(i int64) {
			defer wg.Done()
			// Returns context.Canceled after the bench cancels below.
			_ = qbft.Run(ctx, def, trans, qbftInstance, i,
				qbft.InputValue(qbftValue), qbft.InputValueSource(qbftValue))
		}(i)
	}

	for i := int64(0); i < n; i++ {
		select {
		case <-decided:
		case <-time.After(30 * time.Second):
			b.Fatal("timed out waiting for decide")
		}
	}

	// Teardown is excluded from timing, matching the Rust bench.
	b.StopTimer()
	cancel()
	wg.Wait()
	b.StartTimer()
}

func BenchmarkTier2QbftDecide(b *testing.B) {
	for _, tc := range []struct {
		name string
		n    int64
	}{
		{name: "4of4", n: 4},
		{name: "7of10", n: 10},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				runQbftConsensus(b, tc.n)
			}
		})
	}
}
