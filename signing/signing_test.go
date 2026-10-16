package signing_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/signing"
)

type signingOwner struct{}

type otherOwner struct{}

const input = "eyJhbGciOiJ4In0.eyJzdWIiOiJ1In0"

func minter(t *testing.T) *signing.Minter {
	t.Helper()
	return signing.NewTestMinter()
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

var rsaKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })

func testRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsaKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func pkcs8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func sign(t *testing.T, s signing.Signer) signing.Signed {
	t.Helper()
	sig, err := minter(t).Sign(s, input)
	if err != nil {
		t.Fatal(err)
	}
	return signing.Signed{Algorithm: s.Algorithm(), KeyID: s.KeyID(), Input: input, Signature: sig}
}

func signers(t *testing.T) map[string]signing.Signer {
	t.Helper()
	seed := randomBytes(t, ed25519.SeedSize)
	edPriv := ed25519.NewKeyFromSeed(randomBytes(t, ed25519.SeedSize))
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ecPriv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ecPriv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv := testRSA(t)
	build := map[string]func() (signing.Signer, error){
		"EdDSA seed": func() (signing.Signer, error) { return signing.EdDSA("ed-1", seed) },
		"EdDSA PKCS8 PEM": func() (signing.Signer, error) {
			return signing.EdDSA("ed-2", pemBlock("PRIVATE KEY", pkcs8(t, edPriv)))
		},
		"ES256 PKCS8 DER":  func() (signing.Signer, error) { return signing.ES256("ec-1", pkcs8(t, ecPriv)) },
		"ES256 SEC1 PEM":   func() (signing.Signer, error) { return signing.ES256("ec-2", pemBlock("EC PRIVATE KEY", sec1)) },
		"ES256 raw scalar": func() (signing.Signer, error) { return signing.ES256("ec-3", raw) },
		"RS256 PKCS1 PEM": func() (signing.Signer, error) {
			return signing.RS256("rsa-1", pemBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaPriv)))
		},
		"RS256 PKCS8 DER": func() (signing.Signer, error) { return signing.RS256("rsa-2", pkcs8(t, rsaPriv)) },
		"HS256":           func() (signing.Signer, error) { return signing.HS256("hs-1", randomBytes(t, 32)) },
	}
	out := make(map[string]signing.Signer, len(build))
	for name, f := range build {
		s, err := f()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = s
	}
	return out
}

func TestSignAndVerifyEveryAlgorithm(t *testing.T) {
	for name, s := range signers(t) {
		t.Run(name, func(t *testing.T) {
			signed := sign(t, s)
			if err := s.Verifier().Verify(signed); err != nil {
				t.Fatalf("Verify = %v", err)
			}
			tampered := signed
			tampered.Input = input + "x"
			if err := s.Verifier().Verify(tampered); !errors.Is(err, signing.ErrInvalidSignature) {
				t.Fatalf("Verify(tampered input) = %v", err)
			}
			flipped := signed
			flipped.Signature = bytes.Clone(signed.Signature)
			flipped.Signature[0] ^= 0x01
			if err := s.Verifier().Verify(flipped); !errors.Is(err, signing.ErrInvalidSignature) {
				t.Fatalf("Verify(flipped signature) = %v", err)
			}
		})
	}
}

func TestSignaturesInteroperateWithStandardVerifiers(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	es, err := signing.ES256("ec", pkcs8(t, ecPriv))
	if err != nil {
		t.Fatal(err)
	}
	sig := sign(t, es).Signature
	digest := sha256.Sum256([]byte(input))
	if len(sig) != 64 || !ecdsa.Verify(&ecPriv.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("ES256 signature is not raw r ‖ s over SHA-256")
	}
	seed := randomBytes(t, ed25519.SeedSize)
	ed, err := signing.EdDSA("ed", seed)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), []byte(input), sign(t, ed).Signature) {
		t.Fatal("EdDSA signature does not verify with crypto/ed25519")
	}
}

func TestHS256RawKeyTokenFailsVerification(t *testing.T) {
	key := randomBytes(t, 48)
	s, err := signing.HS256("hs", key)
	if err != nil {
		t.Fatal(err)
	}
	raw := hmac.New(sha256.New, key)
	raw.Write([]byte(input))
	forged := signing.Signed{Algorithm: signing.AlgHS256, KeyID: "hs", Input: input, Signature: raw.Sum(nil)}
	if err := s.Verifier().Verify(forged); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("a token MACed with the raw key verified: %v", err)
	}
	derived, err := hkdf.Key(sha256.New, key, nil, "egauth/jwt-hs256/v2", 32)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, derived)
	mac.Write([]byte(input))
	if got := sign(t, s).Signature; !hmac.Equal(got, mac.Sum(nil)) {
		t.Fatal("HS256 does not MAC with HKDF-SHA256(key, nil, \"egauth/jwt-hs256/v2\")")
	}
}

func TestOneAlgorithmPerKey(t *testing.T) {
	s, err := signing.HS256("k", randomBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	signed := sign(t, s)
	for _, alg := range []string{"none", "", signing.AlgRS256, signing.AlgES256, "hs256"} {
		bad := signed
		bad.Algorithm = alg
		if err := s.Verifier().Verify(bad); !errors.Is(err, signing.ErrInvalidSignature) {
			t.Fatalf("Verify with alg %q = %v", alg, err)
		}
	}
	bad := signed
	bad.KeyID = "other"
	if err := s.Verifier().Verify(bad); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("Verify with another kid = %v", err)
	}
}

func TestWeakKeysAreRejected(t *testing.T) {
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() (signing.Signer, error){
		"HS256 short":         func() (signing.Signer, error) { return signing.HS256("k", randomBytes(t, 31)) },
		"HS256 all zero":      func() (signing.Signer, error) { return signing.HS256("k", make([]byte, 32)) },
		"HS256 repeated text": func() (signing.Signer, error) { return signing.HS256("k", bytes.Repeat([]byte("ab"), 32)) },
		"EdDSA zero seed":     func() (signing.Signer, error) { return signing.EdDSA("k", make([]byte, 32)) },
		"EdDSA garbage":       func() (signing.Signer, error) { return signing.EdDSA("k", randomBytes(t, 40)) },
		"EdDSA RSA key":       func() (signing.Signer, error) { return signing.EdDSA("k", pkcs8(t, testRSA(t))) },
		"ES256 P-384":         func() (signing.Signer, error) { return signing.ES256("k", pkcs8(t, p384)) },
		"ES256 RSA key":       func() (signing.Signer, error) { return signing.ES256("k", pkcs8(t, testRSA(t))) },
		"RS256 1024 bits":     func() (signing.Signer, error) { return signing.RS256("k", x509.MarshalPKCS1PrivateKey(weakRSA)) },
		"RS256 Ed25519 key": func() (signing.Signer, error) {
			return signing.RS256("k", pkcs8(t, ed25519.NewKeyFromSeed(randomBytes(t, 32))))
		},
		"RS256 two PEM blocks": func() (signing.Signer, error) {
			der := x509.MarshalPKCS1PrivateKey(testRSA(t))
			return signing.RS256("k", append(pemBlock("RSA PRIVATE KEY", der), pemBlock("RSA PRIVATE KEY", der)...))
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if s, err := f(); !errors.Is(err, signing.ErrInvalidKey) || !s.IsZero() {
				t.Fatalf("constructor = %v, %v; want ErrInvalidKey and a zero Signer", s, err)
			}
		})
	}
}

func TestSmallRSAExponentIsRejected(t *testing.T) {
	e := big.NewInt(3)
	one := big.NewInt(1)
	prime := func() *big.Int {
		for {
			p, err := rand.Prime(rand.Reader, 1024)
			if err != nil {
				t.Fatal(err)
			}
			if new(big.Int).Mod(new(big.Int).Sub(p, one), e).Sign() != 0 {
				return p
			}
		}
	}
	p, q := prime(), prime()
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	k := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 3},
		D:         new(big.Int).ModInverse(e, phi),
		Primes:    []*big.Int{p, q},
	}
	k.Precompute()
	if err := k.Validate(); err != nil {
		t.Fatalf("test key is inconsistent: %v", err)
	}
	_, err := signing.RS256("k", x509.MarshalPKCS1PrivateKey(k))
	if !errors.Is(err, signing.ErrInvalidKey) || !strings.Contains(err.Error(), "RSA public exponent below 65537") {
		t.Fatalf("RS256(e=3) = %v, want ErrInvalidKey for the exponent", err)
	}
}

func TestInvalidKeyIDs(t *testing.T) {
	key := randomBytes(t, 32)
	for _, kid := range []string{"", "has space", "slash/kid", strings.Repeat("k", 129), "kid\x00"} {
		if _, err := signing.HS256(kid, key); !errors.Is(err, signing.ErrInvalidKeyID) {
			t.Errorf("HS256(%q) = %v, want ErrInvalidKeyID", kid, err)
		}
		if _, err := signing.EdDSA(kid, key); !errors.Is(err, signing.ErrInvalidKeyID) {
			t.Errorf("EdDSA(%q) = %v, want ErrInvalidKeyID", kid, err)
		}
	}
}

func TestConstructorsCopyKeyBytes(t *testing.T) {
	hsKey := randomBytes(t, 32)
	hs, err := signing.HS256("hs", hsKey)
	if err != nil {
		t.Fatal(err)
	}
	seed := randomBytes(t, 32)
	ed, err := signing.EdDSA("ed", seed)
	if err != nil {
		t.Fatal(err)
	}
	before := []signing.Signed{sign(t, hs), sign(t, ed)}
	clear(hsKey)
	clear(seed)
	for i, s := range []signing.Signer{hs, ed} {
		if err := s.Verifier().Verify(before[i]); err != nil {
			t.Fatalf("%s no longer verifies after the caller zeroed its key: %v", s, err)
		}
		after := sign(t, s)
		if !bytes.Equal(after.Signature, before[i].Signature) && s.Algorithm() == signing.AlgHS256 {
			t.Fatal("HS256 signature changed after the caller zeroed its key")
		}
		if err := s.Verifier().Verify(after); err != nil {
			t.Fatalf("%s signs with the caller's zeroed buffer: %v", s, err)
		}
	}
}

func TestSignerIsOpaque(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[signing.Signer](), reflect.TypeFor[*signing.Signer]()} {
		for m := range typ.Methods() {
			if strings.HasPrefix(m.Name, "Sign") {
				t.Errorf("%s exposes %s", typ, m.Name)
			}
			for i := range m.Type.NumOut() {
				out := m.Type.Out(i)
				if out.Kind() == reflect.Slice || out.Kind() == reflect.Interface || out.Kind() == reflect.Pointer {
					t.Errorf("%s.%s returns %s, which could carry key material", typ, m.Name, out)
				}
			}
		}
	}
	for f := range reflect.TypeFor[signing.Signer]().Fields() {
		if f.IsExported() {
			t.Errorf("Signer has exported field %s", f.Name)
		}
	}
}

func TestOnlyEgauthMayMint(t *testing.T) {
	for name, owner := range map[string]any{
		"nil":                  nil,
		"owner outside jwt":    signingOwner{},
		"anonymous struct":     struct{}{},
		"other unexported":     otherOwner{},
		"pointer to owner":     &signingOwner{},
		"standard library":     time.Time{},
		"string named like it": "signingOwner",
	} {
		if m, err := signing.NewMinter(owner); !errors.Is(err, signing.ErrNotOwner) || m != nil {
			t.Errorf("%s: NewMinter = %v, %v; want ErrNotOwner", name, m, err)
		}
	}
	s, err := signing.HS256("k", randomBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	var zero signing.Minter
	if _, err := zero.Sign(s, input); !errors.Is(err, signing.ErrNotOwner) {
		t.Errorf("zero Minter Sign = %v, want ErrNotOwner", err)
	}
	var nilMinter *signing.Minter
	if _, err := nilMinter.Sign(s, input); !errors.Is(err, signing.ErrNotOwner) {
		t.Errorf("nil Minter Sign = %v, want ErrNotOwner", err)
	}
	if _, err := minter(t).Sign(signing.Signer{}, input); !errors.Is(err, signing.ErrZeroKey) {
		t.Errorf("Sign(zero Signer) = %v, want ErrZeroKey", err)
	}
	if err := (signing.Verifier{}).Verify(signing.Signed{}); !errors.Is(err, signing.ErrZeroKey) {
		t.Errorf("zero Verifier Verify = %v, want ErrZeroKey", err)
	}
}

func TestKeysAreRedacted(t *testing.T) {
	key := randomBytes(t, 32)
	s, err := signing.HS256("hs", key)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := hkdf.Key(sha256.New, key, nil, "egauth/jwt-hs256/v2", 32)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("keys", "s", s, "v", s.Verifier())
	out := fmt.Sprintf("%v %+v %#v %v %+v %#v", s, s, s, s.Verifier(), s.Verifier(), s.Verifier()) + buf.String()
	for _, secret := range [][]byte{key, derived} {
		for _, enc := range []string{string(secret), hex.EncodeToString(secret), fmt.Sprintf("%d", secret), base64.StdEncoding.EncodeToString(secret)} {
			if strings.Contains(out, enc) {
				t.Fatalf("formatted keys leak material: %s", out)
			}
		}
	}
}

func TestJWKSRoundTrip(t *testing.T) {
	var public []signing.Signer
	for name, s := range signers(t) {
		if s.Algorithm() == signing.AlgHS256 {
			if _, err := s.Verifier().PublicJWK(); !errors.Is(err, signing.ErrNotPublishable) {
				t.Fatalf("%s: PublicJWK = %v, want ErrNotPublishable", name, err)
			}
			if !s.Verifier().Symmetric() {
				t.Fatal("HS256 verifier is not symmetric")
			}
			continue
		}
		public = append(public, s)
	}
	vs := make([]signing.Verifier, 0, len(public))
	for _, s := range public {
		vs = append(vs, s.Verifier())
	}
	doc, err := signing.EncodeJWKS(vs)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := signing.ParseJWKS(doc)
	if err != nil {
		t.Fatal(err)
	}
	byKID := map[string]signing.Verifier{}
	for _, v := range parsed {
		byKID[v.KeyID()] = v
	}
	for _, s := range public {
		v, ok := byKID[s.KeyID()]
		if !ok || v.Algorithm() != s.Algorithm() {
			t.Fatalf("%s missing or with another algorithm after the round trip", s)
		}
		if err := v.Verify(sign(t, s)); err != nil {
			t.Fatalf("%s: parsed verifier rejects a valid signature: %v", s, err)
		}
	}
}

func TestEncodeJWKSRefusesSymmetricAndDuplicates(t *testing.T) {
	hs, err := signing.HS256("hs", randomBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signing.EncodeJWKS([]signing.Verifier{hs.Verifier()}); !errors.Is(err, signing.ErrNotPublishable) {
		t.Fatalf("EncodeJWKS(HS256) = %v", err)
	}
	a, err := signing.EdDSA("same", randomBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	b, err := signing.ES256("same", pkcs8(t, mustEC(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signing.EncodeJWKS([]signing.Verifier{a.Verifier(), b.Verifier()}); !errors.Is(err, signing.ErrDuplicateKeyID) {
		t.Fatalf("EncodeJWKS(duplicate kid) = %v", err)
	}
	if err := signing.CheckKeyIDs(a.Verifier(), signing.Verifier{}); !errors.Is(err, signing.ErrZeroKey) {
		t.Fatalf("CheckKeyIDs(zero) = %v", err)
	}
}

func mustEC(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseJWKSRejects(t *testing.T) {
	ed, err := signing.EdDSA("ed", randomBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := ed.Verifier().PublicJWK()
	if err != nil {
		t.Fatal(err)
	}
	good := string(jwk)
	x := good[strings.Index(good, `"x":"`)+5:]
	x = x[:strings.Index(x, `"`)]
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallN := base64.RawURLEncoding.EncodeToString(small.N.Bytes())
	cases := map[string]string{
		"not json":            `{`,
		"no keys":             `{"keys":[]}`,
		"alg of other kty":    `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","alg":"RS256","x":"` + x + `"}]}`,
		"missing kid":         `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":"` + x + `"}]}`,
		"only encryption":     `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","alg":"EdDSA","use":"enc","x":"` + x + `"}]}`,
		"only unsupported":    `{"keys":[{"kty":"EC","crv":"P-384","kid":"a","alg":"ES384","x":"` + x + `","y":"` + x + `"}]}`,
		"skipped key private": `{"keys":[` + good + `,{"kty":"RSA","kid":"b","use":"enc","n":"` + smallN + `","e":"AQAB","d":"` + x + `"}]}`,
		"private member":      `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","alg":"EdDSA","x":"` + x + `","d":"` + x + `"}]}`,
		"symmetric":           `{"keys":[{"kty":"oct","kid":"a","alg":"HS256","k":"` + x + `"}]}`,
		"duplicate kid":       `{"keys":[` + good + `,` + good + `]}`,
		"short x":             `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","alg":"EdDSA","x":"AAAA"}]}`,
		"RSA 1024":            `{"keys":[{"kty":"RSA","kid":"a","alg":"RS256","n":"` + smallN + `","e":"AQAB"}]}`,
		"RSA exponent 3":      `{"keys":[{"kty":"RSA","kid":"a","alg":"RS256","n":"` + base64.RawURLEncoding.EncodeToString(testRSA(t).N.Bytes()) + `","e":"Aw"}]}`,
		"EC off curve":        `{"keys":[{"kty":"EC","crv":"P-256","kid":"a","alg":"ES256","x":"` + x + `","y":"` + x + `"}]}`,
		"oversized":           `{"keys":[` + strings.Repeat(" ", 300<<10) + `]}`,
		"alg none":            `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","alg":"none","x":"` + x + `"}]}`,
		"alg case mismatch":   `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","alg":"eddsa","x":"` + x + `"}]}`,
	}
	for name, doc := range cases {
		if _, err := signing.ParseJWKS([]byte(doc)); !errors.Is(err, signing.ErrInvalidJWKS) {
			t.Errorf("%s: ParseJWKS = %v, want ErrInvalidJWKS", name, err)
		}
	}
	if _, err := signing.ParseJWKS([]byte(`{"keys":[` + good + `]}`)); err != nil {
		t.Fatalf("ParseJWKS(valid) = %v", err)
	}
}

func TestJWKSEndpoint(t *testing.T) {
	for _, ok := range []string{"https://idp.example.com/.well-known/jwks.json", "http://127.0.0.1:8080/jwks", "http://localhost/jwks", "http://[::1]/jwks"} {
		e, err := signing.JWKS(ok)
		if err != nil || e.URL() != ok || e.IsZero() {
			t.Errorf("JWKS(%q) = %v, %v", ok, e.URL(), err)
		}
	}
	for _, bad := range []string{
		"", "/jwks", "idp.example.com/jwks", "http://idp.example.com/jwks", "ftp://idp.example.com/jwks",
		"https://user:pass@idp.example.com/jwks", "https://idp.example.com/jwks#frag", "https:///jwks",
		"https://idp.example.com/jwks with space", "javascript:alert(1)",
	} {
		if _, err := signing.JWKS(bad); !errors.Is(err, signing.ErrInvalidURL) {
			t.Errorf("JWKS(%q) = %v, want ErrInvalidURL", bad, err)
		}
	}
	if !(signing.JWKSEndpoint{}).IsZero() {
		t.Error("zero JWKSEndpoint is not zero")
	}
}
