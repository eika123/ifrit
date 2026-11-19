package reconcile_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/reconcile/naive"
	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
	"google.golang.org/grpc"
)

func seedBenchmarkStores(
	b *testing.B,
	strategy string,
	sharedCount, diffCount int,
) (reconcile.Store[string], reconcile.Store[string]) {
	b.Helper()
	hasher := digestmaps.MustDefaultHasher[string]()

	var storeA, storeB reconcile.Store[string]
	var err error
	if strategy == "naive" {
		storeA, err = naive.NewReconcilableStore(hasher)
		if err != nil {
			b.Fatal(err)
		}
		storeB, err = naive.NewReconcilableStore(hasher)
		if err != nil {
			b.Fatal(err)
		}
	} else {
		storeA, err = ratelessIBLT.NewReconcilableStore(hasher)
		if err != nil {
			b.Fatal(err)
		}
		storeB, err = ratelessIBLT.NewReconcilableStore(hasher)
		if err != nil {
			b.Fatal(err)
		}
	}

	shared := make([]string, sharedCount)
	for i := range sharedCount {
		shared[i] = fmt.Sprintf("shared-item-%06d", i)
	}
	storeA.InsertBatch(shared...)
	storeB.InsertBatch(shared...)

	for i := range diffCount {
		storeA.Insert(fmt.Sprintf("diff-a-%06d", i))
		storeB.Insert(fmt.Sprintf("diff-b-%06d", i))
	}
	return storeA, storeB
}

func benchmarkStrategy(b *testing.B, strategy string, sharedCount, diffCount int) {
	b.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	addr := lis.Addr().String()

	srv := grpc.NewServer()
	storeA, storeB := seedBenchmarkStores(b, strategy, sharedCount, diffCount)

	mux := reconcile.NewMux()
	mux.Register(srv)

	recB, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Negotiator: storeB.Negotiator(),
		Codec:      reconcile.DefaultItemCodec[string](),
		Auth:       reconcile.NoopAuthenticator,
		Detector:   reconcile.AcceptAll[string](),
		StoreID:    "data",
		Applier:    reconcile.NoopApplier[string], // keep storeB diff intact across iterations
	})
	if err != nil {
		b.Fatal(err)
	}
	if err := mux.RegisterStore("data", recB); err != nil {
		b.Fatal(err)
	}

	go func() { _ = srv.Serve(lis) }()
	b.Cleanup(srv.Stop)

	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = cc.Close() })

	recA, err := reconcile.NewEngine(storeA, reconcile.Config[string]{
		Negotiator:   storeA.Negotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: func(context.Context, string) (grpc.ClientConnInterface, error) { return cc, nil },
		Detector:     reconcile.AcceptAll[string](),
		StoreID:      "data",
		Applier:      reconcile.NoopApplier[string],
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if _, err := recA.ReconcileWithPeer(ctx, addr); err != nil {
			cancel()
			b.Fatal(err)
		}
		cancel()
	}
}

func BenchmarkReconcile_RIBLT_vs_Naive(b *testing.B) {
	cases := []struct {
		name        string
		sharedCount int
		diffCount   int
	}{
		{name: "10k_10diff", sharedCount: 10000, diffCount: 10},
		{name: "10k_500diff", sharedCount: 10000, diffCount: 500},
	}

	for _, tc := range cases {
		b.Run("RIBLT_"+tc.name, func(b *testing.B) {
			benchmarkStrategy(b, "riblt", tc.sharedCount, tc.diffCount)
		})
		b.Run("Naive_"+tc.name, func(b *testing.B) {
			benchmarkStrategy(b, "naive", tc.sharedCount, tc.diffCount)
		})
	}
}
