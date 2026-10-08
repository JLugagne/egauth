package sealing_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
)

var user = uuid.MustParse("6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5")

func tenant(t *testing.T, s string) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, kek.KeyLength)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func local(t *testing.T, current []byte, previous ...[]byte) *kek.Local {
	t.Helper()
	l, err := kek.NewLocal(current, previous...)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func must(r sealing.Ref, err error) sealing.Ref {
	if err != nil {
		panic(err)
	}
	return r
}

func TestAADFormat(t *testing.T) {
	a := tenant(t, "tenant-a")
	cases := []struct {
		ref  sealing.Ref
		want string
	}{
		{must(sealing.TOTPSecret(principal.Subject{Tenant: a, User: user})), "egauth/totp/v1\x00tenant-a\x00" + user.String()},
		{must(sealing.TOTPSecret(principal.Subject{User: user})), "egauth/totp/v1\x00\x00" + user.String()},
		{must(sealing.OAuthClientSecret(a, "google")), "egauth/oauth-client-secret/v1\x00tenant-a\x00google"},
		{must(sealing.SigningKey(a, "k1")), "egauth/signing-key/v1\x00tenant-a\x00k1"},
		{sealing.DataKey(), "egauth/deployment/v1\x00datakey"},
	}
	for _, c := range cases {
		if got := string(c.ref.AAD()); got != c.want {
			t.Errorf("AAD = %q, want %q", got, c.want)
		}
	}
	if (sealing.Ref{}).AAD() != nil {
		t.Error("zero Ref has an AAD")
	}
}

func TestRefConstructorsRejectBadIDs(t *testing.T) {
	a := tenant(t, "tenant-a")
	if _, err := sealing.TOTPSecret(principal.Subject{Tenant: a}); !errors.Is(err, sealing.ErrInvalidRef) {
		t.Errorf("TOTPSecret(nil user) = %v", err)
	}
	for _, id := range []string{"", "a\x00b", strings.Repeat("x", 257)} {
		if _, err := sealing.OAuthClientSecret(a, id); !errors.Is(err, sealing.ErrInvalidRef) {
			t.Errorf("OAuthClientSecret(%q) = %v", id, err)
		}
		if _, err := sealing.SigningKey(a, id); !errors.Is(err, sealing.ErrInvalidRef) {
			t.Errorf("SigningKey(%q) = %v", id, err)
		}
	}
}

func TestZeroRefIsRefused(t *testing.T) {
	ctx := context.Background()
	k := local(t, randomKey(t))
	if _, err := sealing.Seal(ctx, k, sealing.Ref{}, []byte("x")); !errors.Is(err, sealing.ErrInvalidRef) {
		t.Fatalf("Seal(zero Ref) = %v", err)
	}
	if _, err := sealing.Open(ctx, k, sealing.Ref{}, []byte("x")); !errors.Is(err, sealing.ErrInvalidRef) {
		t.Fatalf("Open(zero Ref) = %v", err)
	}
	if _, err := sealing.OpenLegacy(ctx, nil, sealing.Ref{}, []byte("x")); !errors.Is(err, sealing.ErrInvalidRef) {
		t.Fatalf("OpenLegacy(zero Ref) = %v", err)
	}
}

type recordingKEK struct {
	*kek.Local
	aads []string
}

func (r *recordingKEK) Seal(ctx context.Context, pt []byte, aad kek.AAD) ([]byte, error) {
	r.aads = append(r.aads, string(aad))
	return r.Local.Seal(ctx, pt, aad)
}

func (r *recordingKEK) Open(ctx context.Context, ct []byte, aad kek.AAD) ([]byte, error) {
	r.aads = append(r.aads, string(aad))
	return r.Local.Open(ctx, ct, aad)
}

func TestRoundTripPassesTheRefAAD(t *testing.T) {
	ctx := context.Background()
	rec := &recordingKEK{Local: local(t, randomKey(t))}
	ref := must(sealing.TOTPSecret(principal.Subject{Tenant: tenant(t, "tenant-a"), User: user}))
	ct, err := sealing.Seal(ctx, rec, ref, []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("JBSWY3DPEHPK3PXP")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	got, err := sealing.Open(ctx, rec, ref, ct)
	if err != nil || string(got.Plaintext) != "JBSWY3DPEHPK3PXP" || got.Stale {
		t.Fatalf("Open = %+v, %v", got, err)
	}
	want := string(ref.AAD())
	if len(rec.aads) != 2 || rec.aads[0] != want || rec.aads[1] != want {
		t.Fatalf("KEK saw AADs %q, want two of %q", rec.aads, want)
	}
}

func TestWrongRefFails(t *testing.T) {
	ctx := context.Background()
	k := local(t, randomKey(t))
	a, b := tenant(t, "tenant-a"), tenant(t, "tenant-b")
	ref := must(sealing.OAuthClientSecret(a, "google"))
	ct, err := sealing.Seal(ctx, k, ref, []byte("client-secret"))
	if err != nil {
		t.Fatal(err)
	}
	others := map[string]sealing.Ref{
		"other tenant":   must(sealing.OAuthClientSecret(b, "google")),
		"single tenant":  must(sealing.OAuthClientSecret(principal.TenantID{}, "google")),
		"other row":      must(sealing.OAuthClientSecret(a, "github")),
		"other purpose":  must(sealing.SigningKey(a, "google")),
		"deployment key": sealing.DataKey(),
	}
	for name, other := range others {
		if _, err := sealing.Open(ctx, k, other, ct); !errors.Is(err, kek.ErrOpenFailed) {
			t.Errorf("%s: Open = %v, want kek.ErrOpenFailed", name, err)
		}
	}
}

func TestOpenReportsStaleAfterRotation(t *testing.T) {
	ctx := context.Background()
	oldKey, newKey := randomKey(t), randomKey(t)
	ref := sealing.DataKey()
	ct, err := sealing.Seal(ctx, local(t, oldKey), ref, []byte("data key"))
	if err != nil {
		t.Fatal(err)
	}
	rotated := local(t, newKey, oldKey)
	got, err := sealing.Open(ctx, rotated, ref, ct)
	if err != nil || !got.Stale || string(got.Plaintext) != "data key" {
		t.Fatalf("Open after rotation = %+v, %v; want stale plaintext", got, err)
	}
	resealed, err := sealing.Seal(ctx, rotated, ref, got.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	again, err := sealing.Open(ctx, rotated, ref, resealed)
	if err != nil || again.Stale {
		t.Fatalf("Open after re-seal = %+v, %v; want fresh", again, err)
	}
	if _, err := sealing.Open(ctx, local(t, newKey), ref, resealed); err != nil {
		t.Fatalf("re-sealed value does not open once the old key is dropped: %v", err)
	}
}

func TestOpenedIsRedacted(t *testing.T) {
	o := sealing.Opened{Plaintext: []byte("top-secret-plaintext"), Stale: true}
	if out := fmt.Sprintf("%v %+v %#v %s", o, o, o, o); strings.Contains(out, "top-secret-plaintext") {
		t.Fatalf("Opened leaks its plaintext: %s", out)
	}
}

type legacyFixtures struct {
	Key   string
	Cases []struct{ Name, AAD, Plaintext, Blob string }
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOpenLegacyTriesTheV016AADs(t *testing.T) {
	ctx := context.Background()
	raw, err := os.ReadFile("../../kek/testdata/v016_fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f legacyFixtures
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	legacy, err := kek.LegacyLocalV016(unhex(t, f.Key))
	if err != nil {
		t.Fatal(err)
	}
	a := tenant(t, "tenant-a")
	refs := map[string]sealing.Ref{
		"mfa_totp tenant:user":                 must(sealing.TOTPSecret(principal.Subject{Tenant: a, User: user})),
		"oauth_oidc_providers tenant:provider": must(sealing.OAuthClientSecret(a, "google")),
		"keystore_keys tenant":                 must(sealing.SigningKey(a, "any-kid")),
		"no aad":                               must(sealing.SigningKey(tenant(t, "tenant-z"), "k")),
	}
	for _, c := range f.Cases {
		ref, ok := refs[c.Name]
		if !ok {
			t.Fatalf("no ref for fixture %q", c.Name)
		}
		got, err := sealing.OpenLegacy(ctx, legacy, ref, unhex(t, c.Blob))
		if err != nil || !bytes.Equal(got, unhex(t, c.Plaintext)) {
			t.Errorf("%s: OpenLegacy = %q, %v", c.Name, got, err)
		}
	}
	wrong := must(sealing.TOTPSecret(principal.Subject{Tenant: tenant(t, "tenant-b"), User: user}))
	if _, err := sealing.OpenLegacy(ctx, legacy, wrong, unhex(t, f.Cases[0].Blob)); !errors.Is(err, sealing.ErrLegacyUnopenable) {
		t.Errorf("OpenLegacy under another tenant = %v, want ErrLegacyUnopenable", err)
	}
	if _, err := sealing.OpenLegacy(ctx, legacy, sealing.DataKey(), unhex(t, f.Cases[0].Blob)); !errors.Is(err, sealing.ErrNoLegacyFormat) {
		t.Errorf("OpenLegacy(DataKey) = %v, want ErrNoLegacyFormat", err)
	}
}
