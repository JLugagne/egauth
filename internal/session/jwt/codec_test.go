package jwt_test

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/session/backendtest"
	"github.com/JLugagne/egauth/internal/session/jwt"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

type fieldSpec struct {
	name, tag, typ string
}

func fieldsOf(t reflect.Type) []fieldSpec {
	out := make([]fieldSpec, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		out[i] = fieldSpec{f.Name, f.Tag.Get("json"), f.Type.String()}
	}
	return out
}

func goldenAttrs(t *testing.T, now time.Time, tr core.Transport) core.SessionAttrs {
	t.Helper()
	return principaltest.Attrs(principaltest.Spec{
		Lineage: uuid.MustParse("0a1b2c3d-4e5f-4a6b-9c8d-7e6f5a4b3c2d"),
		Subject: core.Subject{Tenant: tenant(t), User: uuid.MustParse("6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5")},
		Factors: []core.Factor{
			core.FactorPasskey, core.FactorUserVerification, core.FactorPassword, core.FactorTOTP,
			core.FactorPasskeyStepUp, core.FactorFederated,
		},
		PasskeyUses: []principaltest.Credential{
			{Factor: core.FactorPasskey, ID: []byte{1, 2, 3, 4}},
			{Factor: core.FactorPasskeyStepUp, ID: []byte{9, 8, 7}},
		},
		PrimaryAt:       now.Add(-10 * time.Minute),
		SecondAt:        now.Add(-9 * time.Minute),
		Epoch:           7,
		MustChange:      true,
		RememberMe:      true,
		ReturnTo:        "/settings/security?tab=mfa",
		Transport:       tr,
		Provider:        "google",
		CreatedAt:       now.Add(-time.Hour),
		ClaimsFetchedAt: now.Add(-time.Minute),
	})
}

func startBearer(t *testing.T, w *world, a core.SessionAttrs, claims string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := w.backend.Start(t.Context(), rec, a, core.NewSealedClaims([]byte(claims))); err != nil {
		t.Fatal(err)
	}
	return rec.Header().Get(jwt.HeaderAccessToken)
}

// TestClaimSetGolden pins the exhaustive egv 2 claim set of DESIGN §4.5, as a struct and as the
// JSON written for a fixed session.
func TestClaimSetGolden(t *testing.T) {
	want := []fieldSpec{
		{"Iss", "iss", "string"}, {"Aud", "aud", "string"}, {"Sub", "sub", "string"}, {"Tid", "tid", "string"},
		{"Sid", "sid", "string"}, {"Iat", "iat", "int64"}, {"Exp", "exp", "int64"}, {"Typ", "typ", "string"},
		{"Egv", "egv", "int"}, {"Egc", "egc", "string"}, {"Att", "att", "string"}, {"Apc", "apc", reflect.TypeFor[json.RawMessage]().String()},
		{"AMR", "amr", "[]string"}, {"AuthTime", "auth_time", "int64"},
	}
	if got := fieldsOf(jwt.ClaimSetType); !reflect.DeepEqual(got, want) {
		t.Fatalf("claim set changed:\n got %v\nwant %v", got, want)
	}
	if got := fieldsOf(jwt.HeaderType); !reflect.DeepEqual(got, []fieldSpec{{"Alg", "alg", "string"}, {"Kid", "kid", "string"}, {"Typ", "typ", "string"}}) {
		t.Fatalf("header changed: %v", got)
	}

	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, fixedSigner(t))
	tok := startBearer(t, w, goldenAttrs(t, fx.Clock.Now(), core.TransportBearer), `{"roles":["admin"],"custom":{"plan":"pro"}}`)
	parts := strings.Split(tok, ".")
	payload := decodePart(t, parts[1])
	if _, err := uuid.Parse(payload["sid"].(string)); err != nil {
		t.Fatalf("sid is not a uuid: %v", payload["sid"])
	}
	payload["sid"] = "<family>"
	got, err := json.MarshalIndent(map[string]any{"header": decodePart(t, parts[0]), "payload": payload}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "access_token_v2.golden.json")
	if *update {
		if err := os.WriteFile(path, append(got, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(golden)) != string(got) {
		t.Fatalf("access token changed:\n%s\nwant:\n%s", got, golden)
	}
}

// TestAccessTokenClaimsAreIssuerOwnedAcrossRenewal closes T-03 and T-04: the issuer stamps its own
// iss and aud on every token, rotation included, iat is the signing time, and the rotated token is
// accepted by the next request.
func TestAccessTokenClaimsAreIssuerOwnedAcrossRenewal(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	s := mustUser(t, w)
	a := passwordAttrs(t, w, s, core.TransportBearer)
	check := func(tok string) {
		t.Helper()
		at := fx.Clock.Now()
		parts := strings.Split(tok, ".")
		h, p := decodePart(t, parts[0]), decodePart(t, parts[1])
		if h["typ"] != jwt.TokenType || h["alg"] != "EdDSA" || h["kid"] != keyID {
			t.Fatalf("header %v", h)
		}
		iss := "https://acme.example.test"
		switch {
		case p["iss"] != iss, p["aud"] != iss:
			t.Fatalf("issuer and audience are not the issuer's own: %v %v", p["iss"], p["aud"])
		case p["typ"] != jwt.TokenType, p["egv"] != float64(jwt.Version), p["egc"] != fingerprint:
			t.Fatalf("format claims %v %v %v", p["typ"], p["egv"], p["egc"])
		case p["sub"] != s.User.String(), p["tid"] != "acme":
			t.Fatal("subject claims")
		case p["iat"] != float64(at.Unix()):
			t.Fatalf("iat %v, want the signing time %d", p["iat"], at.Unix())
		case p["exp"].(float64)-p["iat"].(float64) > fx.Lifetimes.RecheckEvery.Seconds():
			t.Fatal("exp - iat exceeds RecheckEvery")
		}
		v, err := w.codec.VerifySession(ctx, tok, w.keys)
		if err != nil {
			t.Fatal(err)
		}
		if p["sid"] != v.Family().String() || !v.IssuedAt().Equal(at) {
			t.Fatal("verified token disagrees with its claims")
		}
	}
	access, refresh := startPair(t, w, a)
	check(access)
	for range 3 {
		fx.Clock.Advance(fx.Lifetimes.RecheckEvery + time.Second)
		rec := httptest.NewRecorder()
		if _, err := w.backend.Resume(ctx, rec, bearerRequest(t, access, refresh), tenant(t)); err != nil {
			t.Fatal(err)
		}
		access, refresh = rec.Header().Get(jwt.HeaderAccessToken), rec.Header().Get(jwt.HeaderRefreshToken)
		check(access)
		if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), bearerRequest(t, access, ""), tenant(t)); err != nil {
			t.Fatalf("rotated access token refused by the next request: %v", err)
		}
	}
}

func TestKidPinsAlgorithm(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	tok := startBearer(t, w, goldenAttrs(t, fx.Clock.Now(), core.TransportBearer), `{}`)
	parts := strings.Split(tok, ".")
	header, payload := decodePart(t, parts[0]), decodePart(t, parts[1])
	for _, alg := range []string{"HS256", "RS256", "ES256", "none", ""} {
		h := map[string]any{"alg": alg, "kid": header["kid"], "typ": header["typ"]}
		forged := w.resign(t, h, payload)
		if _, err := w.codec.VerifySession(t.Context(), forged, w.keys); !errors.Is(err, jwt.ErrInvalidToken) {
			t.Fatalf("alg %q accepted under an EdDSA key id: %v", alg, err)
		}
	}
	unsigned := parts[0] + "." + parts[1] + "."
	if _, err := w.codec.VerifySession(t.Context(), unsigned, w.keys); !errors.Is(err, jwt.ErrInvalidToken) {
		t.Fatalf("unsigned token accepted: %v", err)
	}
	other := map[string]any{"alg": header["alg"], "kid": "k2", "typ": header["typ"]}
	if _, err := w.codec.VerifySession(t.Context(), w.resign(t, other, payload), w.keys); !errors.Is(err, jwt.ErrInvalidToken) {
		t.Fatalf("unknown key id accepted: %v", err)
	}
	if _, err := w.codec.VerifySession(t.Context(), tok, w.keys); err != nil {
		t.Fatalf("genuine token refused: %v", err)
	}
}

func TestVerifyRefusesEveryClaimDefect(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	now := fx.Clock.Now()
	tok := startBearer(t, w, goldenAttrs(t, now, core.TransportBearer), `{"roles":["user"]}`)
	parts := strings.Split(tok, ".")
	header, base := decodePart(t, parts[0]), decodePart(t, parts[1])
	edits := map[string]func(p map[string]any){
		"no egv":            func(p map[string]any) { delete(p, "egv") },
		"egv 1":             func(p map[string]any) { p["egv"] = 1 },
		"typ JWT":           func(p map[string]any) { p["typ"] = "JWT" },
		"other egc":         func(p map[string]any) { p["egc"] = "other" },
		"other issuer":      func(p map[string]any) { p["iss"] = "https://evil.example.test" },
		"resource audience": func(p map[string]any) { p["aud"] = resourceAud },
		"audience array":    func(p map[string]any) { p["aud"] = []string{p["aud"].(string)} },
		"iat in the future": func(p map[string]any) {
			p["iat"] = now.Add(time.Minute).Unix()
			p["exp"] = now.Add(2 * time.Minute).Unix()
		},
		"long lifetime":  func(p map[string]any) { p["exp"] = p["iat"].(float64) + fx.Lifetimes.RecheckEvery.Seconds() + 1 },
		"exp before iat": func(p map[string]any) { p["exp"] = p["iat"].(float64) - 1 },
		"other sub":      func(p map[string]any) { p["sub"] = uuid.NewString() },
		"other tid":      func(p map[string]any) { p["tid"] = "other" },
		"nil sid":        func(p map[string]any) { p["sid"] = uuid.Nil.String() },
		"no att":         func(p map[string]any) { delete(p, "att") },
		"garbage att":    func(p map[string]any) { p["att"] = "AAAA" },
		"apc array":      func(p map[string]any) { p["apc"] = []string{"x"} },
		"unknown claim":  func(p map[string]any) { p["roles"] = []string{"admin"} },
	}
	for name, edit := range edits {
		p := map[string]any{}
		for k, v := range base {
			p[k] = v
		}
		edit(p)
		if _, err := w.codec.VerifySession(t.Context(), w.resign(t, header, p), w.keys); !errors.Is(err, jwt.ErrInvalidToken) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	trailing, err := jwt.SignForTest(w.signer, mustJSON(t, header), append(mustJSON(t, base), []byte(" {}")...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.codec.VerifySession(t.Context(), trailing, w.keys); !errors.Is(err, jwt.ErrInvalidToken) {
		t.Errorf("trailing data accepted: %v", err)
	}
	extra := map[string]any{"alg": header["alg"], "kid": header["kid"], "typ": header["typ"], "jku": "https://evil.example.test"}
	if _, err := w.codec.VerifySession(t.Context(), w.resign(t, extra, base), w.keys); !errors.Is(err, jwt.ErrInvalidToken) {
		t.Errorf("unknown header parameter accepted: %v", err)
	}
	for _, malformed := range []string{"", "a.b", tok + ".x", strings.Repeat("a", jwt.MaxTokenLen+1)} {
		if _, err := w.codec.VerifySession(t.Context(), malformed, w.keys); !errors.Is(err, jwt.ErrInvalidToken) {
			t.Errorf("malformed token accepted: %v", err)
		}
	}
	fx.Clock.Advance(fx.Lifetimes.RecheckEvery)
	if _, err := w.codec.VerifySession(t.Context(), tok, w.keys); !errors.Is(err, jwt.ErrExpired) {
		t.Fatalf("token at its exp: %v", err)
	}
}

type countingKeys struct {
	jwt.KeySource
	calls int
}

func (c *countingKeys) Verifier(ctx context.Context, t principal.TenantID, kid string) (signing.Verifier, error) {
	c.calls++
	return c.KeySource.Verifier(ctx, t, kid)
}

// TestVerifyChecksClaimsBeforeLoadingKeys narrows the keyset-cache churn of FOLLOWUPS M11-17: a
// token naming an arbitrary tenant reaches the key source only once its whole claim set is
// consistent.
func TestVerifyChecksClaimsBeforeLoadingKeys(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	tok := startBearer(t, w, goldenAttrs(t, fx.Clock.Now(), core.TransportBearer), `{}`)
	parts := strings.Split(tok, ".")
	header, payload := decodePart(t, parts[0]), decodePart(t, parts[1])
	keys := &countingKeys{KeySource: w.keys}
	for i := range 10 {
		payload["tid"] = "tenant-" + strconv.Itoa(i)
		payload["iss"] = "https://tenant-" + strconv.Itoa(i) + ".example.test"
		payload["aud"] = payload["iss"]
		if _, err := w.codec.VerifySession(t.Context(), w.resign(t, header, payload), keys); !errors.Is(err, jwt.ErrInvalidToken) {
			t.Fatalf("token of another tenant: %v", err)
		}
	}
	if keys.calls != 0 {
		t.Fatalf("inconsistent tokens loaded %d keysets", keys.calls)
	}
	if _, err := w.codec.VerifySession(t.Context(), tok, keys); err != nil || keys.calls != 1 {
		t.Fatalf("genuine token: %v after %d key loads", err, keys.calls)
	}
}
