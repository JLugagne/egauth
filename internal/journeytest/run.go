package journeytest

import (
	"io"
	"log/slog"
	"net/http"
	"testing"
)

// BuildFunc builds the handler of the server under test at publicOrigin and returns the function
// that closes it, the shape of examples/fullstack.BuildServer.
type BuildFunc func(logger *slog.Logger, publicOrigin string) (http.Handler, func() error, error)

// ExampleOrigin is the public origin RunAgainst builds the server for: a loopback origin, so that an
// example on in-memory storage passes the ephemeral-state check of New.
const ExampleOrigin = "http://localhost:8080"

// RunAgainst runs the credentialless G22 battery against the handler build returns, as an example
// smoke test: every auth endpoint it serves is probed for CSRF and request limits, and one unknown
// path must be 404. The OAuth callback bind probe runs only when the server mounts the provider
// named ProviderName; other providers and external factors are not probed. It assumes the default
// BasePath, /auth.
func RunAgainst(t *testing.T, build BuildFunc) {
	t.Helper()
	h, closeFn, err := build(slog.New(slog.NewTextHandler(io.Discard, nil)), ExampleOrigin)
	if err != nil {
		t.Fatalf("journeytest: building the server: %v", err)
	}
	if h == nil {
		t.Fatal("journeytest: build returned a nil handler")
	}
	t.Cleanup(func() {
		if closeFn != nil {
			if err := closeFn(); err != nil {
				t.Errorf("journeytest: closing the server: %v", err)
			}
		}
	})
	c := NewBareClient(t, h, ExampleOrigin)
	probes := AuthProbes(c, "/auth")
	if len(probes) == 0 {
		t.Fatal("journeytest: the server serves no auth endpoint under /auth")
	}
	for _, p := range probes {
		t.Run(p.Name, func(t *testing.T) {
			got, held := p.Run()
			if !held {
				t.Errorf("want %s, got %s", p.Want, got)
			}
		})
	}
}
