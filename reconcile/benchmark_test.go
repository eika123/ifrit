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
	for i := 0; i < sharedCount; i++ {
		shared[i] = fmt.Sprintf("shared-item-%06d", i)
	}
	storeA.InsertBatch(shared...)
	storeB.InsertBatch(shared...)

	for i := 0; i < diffCount; i++ {
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

	var registerMux func(storeID string, rec reconcile.StoreReconciler)
	if strategy == "naive" {
		mux := naive.NewReconcilerMux()
		mux.RegisterGRPC(srv)
		registerMux = func(storeID string, rec reconcile.StoreReconciler) {
			mux.RegisterStore(storeID, rec)
		}
	} else {
		mux := ratelessIBLT.NewReconcilerMux()
		mux.RegisterGRPC(srv)
		registerMux = func(storeID string, rec reconcile.StoreReconciler) {
			mux.RegisterStore(storeID, rec)
		}
	}

	recB := storeB.NewReconciler(reconcile.Config[string]{
		StoreID: "data",
		Applier: func(context.Context, string) error { return nil }, // keep storeB diff intact across iterations
	})
	registerMux("data", recB)

	go func() { _ = srv.Serve(lis) }()
	b.Cleanup(srv.Stop)

	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = cc.Close() })

	recA := storeA.NewReconciler(reconcile.Config[string]{
		ConnProvider: func(context.Context, string) (grpc.ClientConnInterface, error) { return cc, nil },
		StoreID:      "data",
		Applier:      func(context.Context, string) error { return nil },
	})

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
