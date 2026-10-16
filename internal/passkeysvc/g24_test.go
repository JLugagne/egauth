package passkeysvc_test

import (
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/passkeysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/passkey"
	"github.com/JLugagne/egauth/webauthntest"
)

func TestG24DiscouragedResidentKeyMakesDiscoverableLoginFail(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com")
	tok := w.session(sub)
	a := webauthntest.New(origin)
	a.ClientResidentKey = "discouraged"
	a.OmitCredProps = true
	reg := w.register(tok, a)
	if reg.Credential.Discoverable != passkey.Inferred.String() {
		t.Fatalf("stored %q, want inferred", reg.Credential.Discoverable)
	}
	c, _ := w.beginLogin(nil)
	if _, err := a.Get(c.Options); err == nil {
		t.Fatal("a credential created under residentKey discouraged answered a discoverable login")
	}
	honest := webauthntest.New(origin)
	w.register(w.session(sub), honest)
	c, cookies := w.beginLogin(nil)
	expect(t, w.finishLogin(c, cookies, honest.DiscoverableLogin(t, c.Options)), http.StatusOK)
}

func TestG24ClientRewritingResidentKeyIsRefused(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com")
	tok := w.session(sub)
	epoch := w.epoch(sub)
	a := webauthntest.New(origin)
	a.ClientResidentKey = "discouraged"
	c := w.beginRegistration(tok)
	rec := w.finishRegistration(tok, c, a.Register(t, c.Options), nil)
	expect(t, rec, http.StatusConflict)
	if code := errorCode(t, rec); code != "authenticator_cannot_store_passkey" {
		t.Fatalf("error %q", code)
	}
	if n := len(w.credentials(sub)); n != 0 {
		t.Fatalf("%d credentials stored", n)
	}
	if w.epoch(sub) != epoch || len(w.mutator.bumps()) != 0 {
		t.Fatal("a refused registration bumped the epoch")
	}
}

func TestG24AbsentCredPropsStoresInferred(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com")
	silent := webauthntest.New(origin)
	silent.OmitCredProps = true
	w.register(w.session(sub), silent)
	w.register(w.session(sub), webauthntest.New(origin))
	byID := map[string]passkey.DiscoverableState{}
	for _, c := range w.credentials(sub) {
		byID[c.ID.String()] = c.Discoverable
	}
	silentID := passkey.CredentialID(silent.Credentials()[0].ID).String()
	if byID[silentID] != passkey.Inferred {
		t.Fatalf("credProps absent stored %v, want Inferred", byID[silentID])
	}
	for id, st := range byID {
		if id != silentID && st != passkey.Confirmed {
			t.Fatalf("credProps.rk true stored %v, want Confirmed", st)
		}
	}
}

func TestG24ListThenRenameEveryCredentialID(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com")
	tok := w.session(sub)
	for range 3 {
		w.register(tok, webauthntest.New(origin))
	}
	ids := []passkey.CredentialID{{0xfb, 0xff, 0xbf}, {0xff, 0xfe, 0xfd, 0xfc, 0x3e, 0x3f}, {0x00}}
	for range 60 {
		id := make([]byte, 1+len(ids)%64)
		_, _ = rand.Read(id)
		ids = append(ids, id)
	}
	for i, id := range ids {
		w.storeCredential(passkey.Credential{
			Subject: sub, ID: id, PublicKey: []byte{1}, CreatedAt: start.Add(time.Duration(i) * time.Second), Discoverable: passkey.Inferred,
		})
	}
	rec := w.do(req{path: routes.PasskeyCredentials, token: tok, method: http.MethodGet})
	expect(t, rec, http.StatusOK)
	var listed struct {
		Credentials []map[string]any `json:"credentials"`
	}
	decodeInto(t, rec, &listed)
	if len(listed.Credentials) != len(ids)+3 {
		t.Fatalf("listed %d credentials", len(listed.Credentials))
	}
	for i, c := range listed.Credentials {
		id, _ := c["credential_id"].(string)
		nick := "key " + string(rune('a'+i%26))
		rec := w.do(req{path: routes.PasskeyCredentialsRename, token: tok, fields: map[string]any{routes.FieldCredentialID: id, routes.FieldNickname: nick}})
		expect(t, rec, http.StatusOK)
		var out struct {
			Credential passkeysvc.CredentialView `json:"credential"`
		}
		decodeInto(t, rec, &out)
		if out.Credential.CredentialID.String() != id || out.Credential.Nickname != nick {
			t.Fatalf("rename of %s answered %+v", id, out.Credential)
		}
	}
	for _, c := range w.credentials(sub) {
		if c.Nickname == "" {
			t.Fatalf("credential %s was not renamed", c.ID)
		}
	}
}

func TestG24RegistrationOptionsAlwaysRequireAResidentKey(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com")
	tok := w.session(sub)
	w.register(tok, webauthntest.New(origin))
	pk := publicKeyOf(t, w.beginRegistration(tok).Options)
	sel, _ := pk["authenticatorSelection"].(map[string]any)
	if sel["residentKey"] != "required" || sel["requireResidentKey"] != true || sel["userVerification"] != "required" {
		t.Fatalf("authenticatorSelection = %v", sel)
	}
	ext, _ := pk["extensions"].(map[string]any)
	if ext["credProps"] != true {
		t.Fatalf("extensions = %v", ext)
	}
	excluded, _ := pk["excludeCredentials"].([]any)
	if len(excluded) != 1 {
		t.Fatalf("excludeCredentials = %v", pk["excludeCredentials"])
	}
	user, _ := pk["user"].(map[string]any)
	if user["name"] != "alice@example.com" || user["id"] != passkey.CredentialID(sub.User[:]).String() {
		t.Fatalf("user = %v, want the session subject %s", user, sub.User)
	}
}
