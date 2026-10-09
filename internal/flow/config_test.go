package flow_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/flow"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/mfasvc"
	"github.com/JLugagne/egauth/internal/routes"
)

func TestNewReportsEveryMissingMember(t *testing.T) {
	_, err := flow.New(flow.Config{})
	if !errors.Is(err, flow.ErrInvalidConfig) {
		t.Fatalf("New(zero) = %v", err)
	}
	for _, name := range []string{"Flows", "Cookies", "Audit"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error does not name %s: %v", name, err)
		}
	}
}

func TestEndpointsRefuseANilIssuer(t *testing.T) {
	w := newWorld(t)
	if _, err := w.flow.Endpoints(nil); !errors.Is(err, flow.ErrNilIssuer) {
		t.Fatalf("Endpoints(nil) = %v", err)
	}
}

// TestCompletesFollowsTheServedEndpoints pins the single source of the offered factors: a factor
// is offered exactly when an endpoint completing it is served.
func TestCompletesFollowsTheServedEndpoints(t *testing.T) {
	cases := []struct {
		o     options
		done  []core.Factor
		paths []string
	}{
		{o: options{}, done: []core.Factor{core.FactorTOTP, core.FactorRecoveryCode, core.FactorPasskeyStepUp},
			paths: []string{routes.Reauth, routes.MFAChallenge, routes.MFAPasskeyBegin, routes.MFAPasskeyFinish}},
		{o: options{noMFAModule: true}, done: []core.Factor{core.FactorPasskeyStepUp},
			paths: []string{routes.Reauth, routes.MFAPasskeyBegin, routes.MFAPasskeyFinish}},
		{o: options{noPasskeyModule: true}, done: []core.Factor{core.FactorTOTP, core.FactorRecoveryCode},
			paths: []string{routes.Reauth, routes.MFAChallenge}},
		{o: options{noMFAModule: true, noPasskeyModule: true}, paths: []string{routes.Reauth}},
	}
	all := []core.Factor{core.FactorTOTP, core.FactorRecoveryCode, core.FactorPasskeyStepUp, core.FactorPassword, core.FactorPasskey, {}}
	for _, c := range cases {
		w := newWorldWith(t, c.o)
		for _, f := range all {
			if got := w.flow.Completes(f); got != slices.Contains(c.done, f) {
				t.Errorf("%+v: Completes(%q) = %v", c.o, f.Code(), got)
			}
		}
		eps, err := w.flow.Endpoints(w.issuer)
		must(t, err)
		var paths []string
		for _, e := range eps {
			paths = append(paths, e.Path)
		}
		if !slices.Equal(paths, c.paths) {
			t.Errorf("%+v: endpoints %v, want %v", c.o, paths, c.paths)
		}
	}
}

func TestTypedNilOptionalMembersAreAbsent(t *testing.T) {
	w := newWorld(t)
	var second *mfasvc.Service
	s, err := flow.New(flow.Config{Flows: w.ceremonies, Cookies: w.cookies, SecondFactors: second, Audit: httpx.SinkAudit(w.sink)})
	must(t, err)
	if s.Completes(core.FactorTOTP) {
		t.Fatal("a typed nil SecondFactors must count as absent")
	}
}
