package argon2

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passwords"
)

func TestKeyDerivationsAreBoundedPerProcess(t *testing.T) {
	var inFlight, peak atomic.Int64
	release := make(chan struct{})
	idKey = func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		inFlight.Add(-1)
		return make([]byte, keyLen)
	}
	t.Cleanup(func() { idKey = realIDKey })
	h, stored := NewHasher(), mustHash(t)
	callers := 8 * max(2, runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			if i%2 == 0 {
				_, _ = h.Hash(context.Background(), "correct horse")
				return
			}
			_ = h.Compare(context.Background(), passwords.PHC(stored), "correct horse")
		})
	}
	limit := int64(max(2, runtime.GOMAXPROCS(0)))
	for deadline := time.Now().Add(5 * time.Second); peak.Load() < limit && time.Now().Before(deadline); {
		runtime.Gosched()
	}
	close(release)
	wg.Wait()
	if got := peak.Load(); got > limit {
		t.Fatalf("%d Argon2id derivations ran at once (64 MiB each), want at most %d: concurrent logins exhaust memory", got, limit)
	}
}

func TestAWaitingDerivationHonoursItsContext(t *testing.T) {
	release := make(chan struct{})
	idKey = func(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
		<-release
		return make([]byte, keyLen)
	}
	t.Cleanup(func() { idKey = realIDKey })
	h := NewHasher()
	var wg sync.WaitGroup
	for range max(2, runtime.GOMAXPROCS(0)) {
		wg.Go(func() { _, _ = h.Hash(context.Background(), "busy") })
	}
	for deadline := time.Now().Add(5 * time.Second); len(derivations) < cap(derivations) && time.Now().Before(deadline); {
		runtime.Gosched()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := h.Hash(ctx, "queued")
		done <- err
	}()
	select {
	case err := <-done:
		close(release)
		wg.Wait()
		if err == nil {
			t.Fatal("a derivation queued behind a full budget ignored its deadline")
		}
	case <-time.After(2 * time.Second):
		close(release)
		wg.Wait()
		t.Fatal("a derivation queued behind a full budget was still running two seconds after its deadline")
	}
}

var realIDKey = idKey

func mustHash(t *testing.T) string {
	t.Helper()
	saved := idKey
	idKey = realIDKey
	defer func() { idKey = saved }()
	s, err := NewHasher().Hash(context.Background(), "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
