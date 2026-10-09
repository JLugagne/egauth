package passkeysvc_test

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/passkeysvc"
	"github.com/JLugagne/egauth/internal/routes"
)

func leaks(s string, key []byte) bool {
	decimal := strings.Trim(fmt.Sprint(key), "[]")
	gosyntax := strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", key), "[]byte{"), "}")
	for _, form := range []string{string(key), decimal, gosyntax, hex.EncodeToString(key), base64.StdEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key)} {
		if strings.Contains(s, form) {
			return true
		}
	}
	return false
}

func TestLeaksDetectsEveryRendering(t *testing.T) {
	key := testDataKey()
	for _, s := range []string{fmt.Sprintf("%v", key), fmt.Sprintf("%+v", struct{ K []byte }{key}), fmt.Sprintf("%x", key), fmt.Sprintf("%#v", key)} {
		if !leaks(s, key) {
			t.Errorf("leaks missed %q", s)
		}
	}
}

func TestUnverifiedEmailCannotLogInWithAPasskey(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	w.unverified.Store(sub, true)
	c, cookies := w.beginLogin(nil)
	rec := w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options))
	expect(t, rec, http.StatusUnauthorized)
	if code := errorCode(t, rec); code != passkeysvc.ErrPasskeyRejected.Code() {
		t.Fatalf("error %q", code)
	}
	if n := len(w.issuer.completions()); n != 0 {
		t.Fatalf("an unverified account reached Issuer.Complete %d times", n)
	}
	c, _ = w.beginLogin(map[string]any{routes.FieldIdentifier: "alice@example.com"})
	if slices.Contains(allowed(t, c.Options), b64(a.Credentials()[0].ID)) {
		t.Fatal("an unverified account's real credential ids were disclosed")
	}
	w.unverified.Delete(sub)
	c, cookies = w.beginLogin(nil)
	expect(t, w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options)), http.StatusOK)
}

func TestServiceRedactsItsKeys(t *testing.T) {
	w := newWorld(t)
	decoy, err := hkdf.Key(sha256.New, testDataKey(), nil, "egauth/passkey-decoy/v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("service", "svc", w.svc, "value", *w.svc)
	s := fmt.Sprintf("%v %+v %#v %v %+v %#v %s", *w.svc, *w.svc, *w.svc, w.svc, w.svc, w.svc, buf.String())
	if leaks(s, decoy) || leaks(s, testDataKey()) {
		t.Fatalf("the service prints a key: %s", s)
	}
}

func TestLoginKeepsAConcurrentRename(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	c, cookies := w.beginLogin(nil)
	body := a.DiscoverableLogin(t, c.Options)
	rename := func() {
		cur := w.credentials(sub)[0]
		cur.Nickname = "renamed meanwhile"
		if err := w.hooks.Store.Update(context.Background(), cur); err != nil {
			t.Error(err)
		}
	}
	w.hooks.afterSignCount.Store(&rename)
	expect(t, w.finishLogin(c, cookies, body), http.StatusOK)
	got := w.credentials(sub)[0]
	if got.Nickname != "renamed meanwhile" || got.LastUsedAt == nil {
		t.Fatalf("nickname %q last use %v", got.Nickname, got.LastUsedAt)
	}
}

func TestRenameKeepsAConcurrentLogin(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	tok := w.session(sub)
	c, cookies := w.beginLogin(nil)
	body := a.DiscoverableLogin(t, c.Options)
	done := make(chan int, 1)
	login := func() {
		go func() { done <- w.finishLogin(c, cookies, body).Code }()
		select {
		case code := <-done:
			done <- code
		case <-time.After(300 * time.Millisecond):
		}
	}
	w.hooks.afterGet.Store(&login)
	rec := w.do(req{path: routes.PasskeyCredentialsRename, token: tok, fields: map[string]any{
		routes.FieldCredentialID: b64(a.Credentials()[0].ID), routes.FieldNickname: "Laptop",
	}})
	expect(t, rec, http.StatusOK)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("login %d", code)
	}
	got := w.credentials(sub)[0]
	if got.Nickname != "Laptop" || got.LastUsedAt == nil {
		t.Fatalf("nickname %q last use %v", got.Nickname, got.LastUsedAt)
	}
}
