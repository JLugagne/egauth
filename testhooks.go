package egauth

import (
	"errors"
	"runtime"
	"strings"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/configcheck"
	"github.com/JLugagne/egauth/principal"
)

// TestClock is the library clock, named here so that memstore.NewWithClock can take the clock of
// an egauthtest.Clock without importing internal/clock. Its zero value reads the wall clock; only
// egauthtest.Clock.Library returns one that does not.
type TestClock = clock.Clock

const hookCaller = "github.com/JLugagne/egauth/egauthtest."

var errHookCaller = errors.New("egauth: test hooks may be called only by package egauthtest")

// TestHookSessionPrincipal builds a session Principal from attrs, bypassing every gate. It checks
// its caller at run time and returns an error unless that caller is in package egauthtest; the
// repository guard test also fails on any other caller.
func TestHookSessionPrincipal[C any](attrs principal.SessionAttrs, claims AppClaims[C]) (Principal[C], error) {
	if !calledByEgauthtest() {
		return Principal[C]{}, errHookCaller
	}
	return sessionPrincipal(attrs, claims)
}

// TestHookAPIKeyPrincipal builds an API-key Principal from info, bypassing every gate. Like
// TestHookSessionPrincipal it returns an error unless called from package egauthtest.
func TestHookAPIKeyPrincipal[C any](info APIKeyInfo, claims AppClaims[C]) (Principal[C], error) {
	if !calledByEgauthtest() {
		return Principal[C]{}, errHookCaller
	}
	return apiKeyPrincipal(info, claims)
}

// TestHookDevelopmentAck returns an acknowledgement that New accepts only when every origin and
// audience is loopback, so the opt-outs of egauthtest.Config cannot reach a public deployment. It
// returns nil, which New refuses, unless called from package egauthtest.
func TestHookDevelopmentAck(reason string) *Ack {
	if !calledByEgauthtest() {
		return nil
	}
	return &Ack{reason: reason, development: true}
}

// TestHookResolve applies the defaults registry to a copy of cfg and returns the resolved view with
// every validation error. Called from outside package egauthtest it returns no view and a single
// error.
func TestHookResolve[C any](cfg Config[C]) (*configcheck.Resolved, []*configcheck.Error) {
	if !calledByEgauthtest() {
		return nil, []*configcheck.Error{{Problem: errHookCaller.Error()}}
	}
	cfg = snapshot(cfg)
	return configcheck.Validate(&cfg, configOptions(&cfg))
}

func calledByEgauthtest() bool {
	pcs := make([]uintptr, 8)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		if !strings.HasPrefix(f.Function, "github.com/JLugagne/egauth.TestHook") {
			return strings.HasPrefix(f.Function, hookCaller)
		}
		if !more {
			return false
		}
	}
}
