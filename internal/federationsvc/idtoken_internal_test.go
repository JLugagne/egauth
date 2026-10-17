package federationsvc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/clock"
)

type countingDoer struct {
	body  string
	calls int
}

func (d *countingDoer) Do(*http.Request) (*http.Response, error) {
	d.calls++
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(d.body))}, nil
}

func edJWKS(t *testing.T, kid string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{"keys": []map[string]string{
		{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUnknownKidRefetchesAtMostOncePerMinRefresh(t *testing.T) {
	clk := clock.NewTest(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	d := &countingDoer{body: edJWKS(t, "known")}
	cache := newJWKSCache(clk.Clock())
	ctx := context.Background()

	if _, err := cache.key(ctx, d, "https://idp.example/jwks", "known"); err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		_, err := cache.key(ctx, d, "https://idp.example/jwks", "unknown-"+string(rune('a'+i%26)))
		if !errors.Is(err, ErrInvalidIdentity) {
			t.Fatalf("attempt %d: err = %v, want ErrInvalidIdentity", i, err)
		}
	}
	if d.calls != 1 {
		t.Fatalf("jwks fetched %d times within the minimum refresh window, want 1", d.calls)
	}

	clk.Advance(jwksMinRefresh + time.Second)
	if _, err := cache.key(ctx, d, "https://idp.example/jwks", "unknown"); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("err = %v, want ErrInvalidIdentity", err)
	}
	if _, err := cache.key(ctx, d, "https://idp.example/jwks", "unknown2"); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("err = %v, want ErrInvalidIdentity", err)
	}
	if d.calls != 2 {
		t.Fatalf("jwks fetched %d times after the window elapsed, want 2", d.calls)
	}
}
