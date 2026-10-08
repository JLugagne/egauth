package signing_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/secretpolicy"
	"github.com/JLugagne/egauth/signing"
)

func TestHS256RejectsEveryPublishedCredential(t *testing.T) {
	for denied := range secretpolicy.Denied {
		if len(denied) < secretpolicy.MinKeyLength {
			t.Fatalf("secretpolicy.Denied entry %q is shorter than an HS256 key; extend this test", denied)
		}
		if s, err := signing.HS256("k1", []byte(denied)); !errors.Is(err, signing.ErrInvalidKey) || !s.IsZero() {
			t.Errorf("HS256(%q) = %v, %v; want ErrInvalidKey", denied, s, err)
		}
		if len(denied) != ed25519.SeedSize {
			continue
		}
		if _, err := signing.EdDSA("k1", []byte(denied)); !errors.Is(err, signing.ErrInvalidKey) {
			t.Errorf("EdDSA(%q) = %v; want ErrInvalidKey", denied, err)
		}
		if _, err := signing.ES256("k1", []byte(denied)); !errors.Is(err, signing.ErrInvalidKey) {
			t.Errorf("ES256(%q) = %v; want ErrInvalidKey", denied, err)
		}
	}
}

func TestHS256RejectsPublishedNearCopies(t *testing.T) {
	nearCopy := []byte("my-own-minimum-hs256-signing-secret-variant")
	if err := secretpolicy.Validate("HS256", nearCopy, secretpolicy.MinKeyLength); !errors.Is(err, secretpolicy.ErrNearCopy) {
		t.Fatalf("fixture is not a near-copy for secretpolicy: %v", err)
	}
	if _, err := signing.HS256("k1", nearCopy); !errors.Is(err, signing.ErrInvalidKey) {
		t.Fatalf("HS256(near-copy) = %v, want ErrInvalidKey", err)
	}
}

func TestParseJWKSAcceptsThirdPartyDocuments(t *testing.T) {
	rsaPriv := testRSA(t)
	rs, err := signing.RS256("entra-kid", pkcs8(t, rsaPriv))
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(rsaPriv.N.Bytes())
	p384 := base64.RawURLEncoding.EncodeToString(make([]byte, 48))
	doc := `{"keys":[
		{"kty":"RSA","use":"sig","kid":"entra-kid","x5t":"abc","n":"` + n + `","e":"AQAB","x5c":["MIIB"]},
		{"kty":"RSA","use":"enc","kid":"entra-kid","alg":"RSA-OAEP","n":"` + n + `","e":"AQAB"},
		{"kty":"RSA","kid":"ps","alg":"PS256","n":"` + n + `","e":"AQAB"},
		{"kty":"EC","crv":"P-384","kid":"ec384","alg":"ES384","x":"` + p384 + `","y":"` + p384 + `"},
		{"kty":"OKP","crv":"X25519","kid":"xdh","x":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}
	]}`
	vs, err := signing.ParseJWKS([]byte(doc))
	if err != nil {
		t.Fatalf("ParseJWKS(third-party document) = %v", err)
	}
	if len(vs) != 1 || vs[0].KeyID() != "entra-kid" || vs[0].Algorithm() != signing.AlgRS256 {
		t.Fatalf("ParseJWKS kept %v, want only the RS256 signing key", vs)
	}
	if err := vs[0].Verify(sign(t, rs)); err != nil {
		t.Fatalf("verifier from a JWK without alg rejects an RS256 signature: %v", err)
	}
	ps := sign(t, rs)
	ps.Algorithm = "PS256"
	if err := vs[0].Verify(ps); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("a JWK without alg verifies another algorithm: %v", err)
	}
}

func TestParseJWKSInfersOnlyTheKeyTypeAlgorithm(t *testing.T) {
	ed, err := signing.EdDSA("ed", randomBytes(t, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	ec, err := signing.ES256("ec", pkcs8(t, mustEC(t)))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, s := range []signing.Signer{ed, ec} {
		j, err := s.Verifier().PublicJWK()
		if err != nil {
			t.Fatal(err)
		}
		stripped := strings.Replace(string(j), `"alg":"`+s.Algorithm()+`",`, "", 1)
		if stripped == string(j) {
			t.Fatalf("PublicJWK layout changed: %s", j)
		}
		keys = append(keys, stripped)
	}
	vs, err := signing.ParseJWKS([]byte(`{"keys":[` + strings.Join(keys, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range vs {
		got[v.KeyID()] = v.Algorithm()
	}
	if got["ed"] != signing.AlgEdDSA || got["ec"] != signing.AlgES256 || len(got) != 2 {
		t.Fatalf("inferred algorithms = %v", got)
	}
	for i, s := range []signing.Signer{ed, ec} {
		if err := vs[i].Verify(sign(t, s)); err != nil {
			t.Fatalf("inferred %s verifier rejects a valid signature: %v", s.Algorithm(), err)
		}
	}
}
