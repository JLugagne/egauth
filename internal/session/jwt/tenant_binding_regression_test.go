package jwt_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JLugagne/egauth/internal/core"
	internalkeys "github.com/JLugagne/egauth/internal/keys"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/backendtest"
	"github.com/JLugagne/egauth/internal/session/jwt"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
	storekeys "github.com/JLugagne/egauth/store/keys"
	keysmemory "github.com/JLugagne/egauth/store/keys/memory"
)

// countingKeyStore counts the keyset reads a TenantKeys manager makes.
type countingKeyStore struct {
	*keysmemory.Store
	reads atomic.Int64
}

func (c *countingKeyStore) VerificationKeys(ctx context.Context, t principal.TenantID) ([]storekeys.Key, error) {
	c.reads.Add(1)
	return c.Store.VerificationKeys(ctx, t)
}

// forgedTenantBackend returns a TenantKeys backend over a counting key store and an access token
// whose sealed "att", "tid", "iss" and "aud" were relabelled with the unknown tenant "evil". The
// encoding stays canonical, so every pre-signature claim check passes; only the signature is wrong.
func forgedTenantBackend(t *testing.T) (*jwt.Backend, *countingKeyStore, string) {
	t.Helper()
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	genuine := startBearer(t, w, goldenAttrs(t, fx.Clock.Now(), core.TransportBearer), `{}`)
	parts := strings.Split(genuine, ".")
	if len(parts) != 3 {
		t.Fatalf("genuine token is not a compact JWS")
	}
	payload := decodePart(t, parts[1])
	att, err := base64.RawURLEncoding.DecodeString(payload["att"].(string))
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(att, append([]byte{4}, []byte("acme")...))
	if at < 0 {
		t.Fatalf("tenant string not found in the sealed attributes")
	}
	copy(att[at+1:], []byte("evil"))
	payload["att"] = base64.RawURLEncoding.EncodeToString(att)
	payload["tid"] = "evil"
	payload["iss"] = "https://evil.example.test"
	payload["aud"] = payload["iss"]
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(mustJSON(t, payload)) + "." + parts[2]

	cs := &countingKeyStore{Store: keysmemory.New()}
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	dek, err := kek.NewLocal(material)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := internalkeys.NewTenant(internalkeys.TenantConfig{Store: cs, KEK: dek, Clock: fx.Clock.Clock(), Events: fx.Events})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	renewer, err := session.NewRenewer(session.RenewConfig{
		Authority: authority{id: w.identity, enr: fx.Enrollment}, Claims: fx.Claims,
		Lifetimes: fx.Lifetimes, Clock: fx.Clock.Clock(), Events: fx.Events,
	})
	if err != nil {
		t.Fatal(err)
	}
	be, err := jwt.New(jwt.Config{
		Codec: w.codec, Keys: mgr, Tokens: w.tokens, Families: w.families, Epochs: w.epochs,
		Renewer: renewer, Cookies: w.cookies, Audiences: []string{resourceAud},
		Clock: fx.Clock.Clock(), Events: fx.Events,
	})
	if err != nil {
		t.Fatal(err)
	}
	cs.reads.Store(0)
	return be, cs, forged
}

// TestTenantBinding_ForgedTenantResumeCausesNoKeyStoreRead pins F-TJK-001 on Resume: a token
// naming another tenant than the one the request resolved to is refused before any key lookup,
// so an unauthenticated client cannot force a keys-store read per request.
func TestTenantBinding_ForgedTenantResumeCausesNoKeyStoreRead(t *testing.T) {
	be, cs, forged := forgedTenantBackend(t)
	if _, err := be.Resume(t.Context(), httptest.NewRecorder(), bearerRequest(t, forged, ""), tenant(t)); err == nil {
		t.Fatalf("a token relabelled with another tenant authenticated")
	}
	if got := cs.reads.Load(); got != 0 {
		t.Fatalf("a token naming tenant %q caused %d keys-store read(s); want 0", "evil", got)
	}
}

// TestTenantBinding_ForgedTenantEndCausesNoKeyStoreRead pins F-TJK-001 on End (POST /logout):
// a token naming another tenant only clears; it neither loads that tenant's keyset nor fails.
func TestTenantBinding_ForgedTenantEndCausesNoKeyStoreRead(t *testing.T) {
	be, cs, forged := forgedTenantBackend(t)
	if err := be.End(t.Context(), httptest.NewRecorder(), bearerRequest(t, forged, ""), tenant(t)); err != nil {
		t.Fatalf("End with a token of another tenant: %v", err)
	}
	if got := cs.reads.Load(); got != 0 {
		t.Fatalf("logging out with a token naming tenant %q caused %d keys-store read(s); want 0", "evil", got)
	}
}
