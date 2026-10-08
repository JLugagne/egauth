package identitysvc_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
)

func login(w *world, id, pw string) (int, string) {
	rec := w.do(req{path: routes.Login, fields: map[string]string{"identifier": id, "password": pw}})
	return rec.Code, rec.Body.String()
}

func TestLoginAdmitsWithThePasswordFactor(t *testing.T) {
	w := newWorld(t)
	sub := w.createVerified("alice@example.com", goodPass)
	code, body := login(w, " Alice@Example.COM ", goodPass)
	if code != http.StatusOK {
		t.Fatalf("login = %d %s", code, body)
	}
	got := w.issuer.admissions()
	if len(got) != 1 || got[0].subject != sub || !slices.Equal(got[0].factors, []core.Factor{core.FactorPassword}) {
		t.Fatalf("admissions = %+v", got)
	}
}

func TestLoginComparesTheNFKCFormAndAcceptsALegacyRawHash(t *testing.T) {
	w := newWorld(t)
	w.createVerified("nfkc@example.com", "Ｃｏｒｒｅｃｔ horse")
	if code, body := login(w, "nfkc@example.com", "Correct horse"); code != http.StatusOK {
		t.Fatalf("NFKC-equivalent password = %d %s", code, body)
	}
	id, _ := identitysvc.Normalize("legacy@example.com")
	if _, err := w.identity.Apply(context.Background(), identity.CreateVerified{Email: id, PHC: identity.NewPasswordHash("$fake$Ｌｅｇａｃｙ pass")}); err != nil {
		t.Fatal(err)
	}
	if code, body := login(w, "legacy@example.com", "Ｌｅｇａｃｙ pass"); code != http.StatusOK {
		t.Fatalf("v0.16 hash of the raw form = %d %s", code, body)
	}
}

func TestLoginFailuresAreUniformAndAlwaysHash(t *testing.T) {
	unv := (*unverifiedStore)(nil)
	w := newWorldWrapping(t, func(s identity.Store) identity.Store {
		unv = newUnverifiedStore(s)
		return unv
	})
	ctx := context.Background()
	w.createVerified("good@example.com", goodPass)
	disabled := w.createVerified("disabled@example.com", goodPass)
	if _, err := w.identity.Apply(ctx, identity.SetDisabledState{Subject: disabled, Disable: true}); err != nil {
		t.Fatal(err)
	}
	unverified := w.createVerified("unverified@example.com", goodPass)
	unv.setUnverified(unverified)
	w.createVerified("federated@example.com", "")
	deleted := w.createVerified("deleted@example.com", goodPass)
	if _, err := w.identity.Apply(ctx, identity.Tombstone{Subject: deleted}); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, id, pw string }{
		{"wrong password", "good@example.com", "wrong password!"},
		{"unknown identifier", "nobody@example.com", goodPass},
		{"malformed identifier", "not an identifier", goodPass},
		{"disabled", "disabled@example.com", goodPass},
		{"unverified email", "unverified@example.com", goodPass},
		{"no password", "federated@example.com", goodPass},
		{"deleted", "deleted@example.com", goodPass},
		{"unknown phone", "+33612345678", goodPass},
	}
	var first string
	for _, c := range cases {
		before := w.hasher.compares.Load()
		code, body := login(w, c.id, c.pw)
		if code != http.StatusUnauthorized {
			t.Errorf("%s: status %d", c.name, code)
		}
		if first == "" {
			first = body
		}
		if body != first {
			t.Errorf("%s: body %q differs from %q", c.name, body, first)
		}
		if w.hasher.compares.Load() == before {
			t.Errorf("%s: answered without a full or decoy hash", c.name)
		}
	}
	if first != "{\"error\":\"invalid_credentials\"}\n" {
		t.Fatalf("body = %q", first)
	}
	if len(w.issuer.admissions()) != 0 {
		t.Fatal("a refused login reached the issuer")
	}
	if !w.sink.has(event.LoginFailed) {
		t.Fatal("no login.failed event")
	}
}

func TestLoginLocksAfterRepeatedFailures(t *testing.T) {
	w := newWorld(t)
	w.createVerified("lock@example.com", goodPass)
	for range identitysvc.LockoutThreshold {
		if code, _ := login(w, "lock@example.com", "wrong password!"); code != http.StatusUnauthorized {
			t.Fatalf("status %d", code)
		}
	}
	if !w.sink.has(event.AccountLocked) {
		t.Fatalf("events = %v", w.sink.types())
	}
	if code, body := login(w, "lock@example.com", goodPass); code != http.StatusUnauthorized || body != "{\"error\":\"invalid_credentials\"}\n" {
		t.Fatalf("a locked credential admitted the right password: %d %s", code, body)
	}
	w.clock.Advance(identitysvc.LockoutWindow + time.Second)
	if code, _ := login(w, "lock@example.com", goodPass); code != http.StatusOK {
		t.Fatalf("after the window: %d", code)
	}
}

func TestLoginLimiterKeyIsTheNormalisedIdentifier(t *testing.T) {
	w := newWorld(t)
	login(w, "User@Example.COM", "x")
	login(w, " user@example.com", "x")
	login(w, "ｕｓｅｒ@example.com", "x")
	keys := w.limiter.identifierKeys()
	if len(keys) != 3 || keys[0] != "email:user@example.com" || keys[1] != keys[0] || keys[2] != keys[0] {
		t.Fatalf("identifier keys = %q", keys)
	}
}

func TestLoginIsUniformWhenThePasswordTableFails(t *testing.T) {
	var unv *unverifiedStore
	w := newWorldWrapping(t, func(s identity.Store) identity.Store {
		unv = newUnverifiedStore(s)
		return unv
	})
	w.createVerified("good@example.com", goodPass)
	unv.passErr = errors.New("password table unavailable")
	knownCode, knownBody := login(w, "good@example.com", goodPass)
	unknownCode, unknownBody := login(w, "nobody@example.com", goodPass)
	if knownCode != unknownCode || knownBody != unknownBody {
		t.Fatalf("a password table outage tells accounts apart: known=%d %q unknown=%d %q", knownCode, knownBody, unknownCode, unknownBody)
	}
	if knownCode != http.StatusServiceUnavailable {
		t.Fatalf("an outage must not answer as a wrong password: %d %q", knownCode, knownBody)
	}
}
