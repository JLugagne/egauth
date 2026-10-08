// Package kektest is the contract suite every kek.KEK implementation runs (G11).
package kektest

import (
	"context"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/kek"
)

// Run checks the KEK contract against a fresh KEK from newKEK, sequentially and from concurrent
// goroutines.
func Run(t *testing.T, newKEK func(*testing.T) kek.KEK) {
	t.Helper()
	t.Run("conformance", func(t *testing.T) {
		if err := kek.CheckConformance(context.Background(), newKEK(t)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		k := newKEK(t)
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for range 8 {
			wg.Go(func() {
				errs <- kek.CheckConformance(context.Background(), k)
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	})
}
