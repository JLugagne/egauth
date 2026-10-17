package signing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxJWKSBytes = 256 << 10
	maxJWKSKeys  = 64
	maxJWKKidLen = 256
)

type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type jwkSet struct {
	Keys []json.RawMessage `json:"keys"`
}

var b64 = base64.RawURLEncoding

// PublicJWK returns the RFC 7517 public JWK of v, with "kid", "alg" and "use":"sig". A symmetric
// key returns ErrNotPublishable.
func (v Verifier) PublicJWK() ([]byte, error) {
	j, err := v.jwk()
	if err != nil {
		return nil, err
	}
	return json.Marshal(j)
}

func (v Verifier) jwk() (jwk, error) {
	if v.k == nil {
		return jwk{}, ErrZeroKey
	}
	k := v.k
	j := jwk{Alg: k.alg, Kid: k.kid, Use: "sig"}
	switch {
	case k.ed != nil:
		j.Kty, j.Crv, j.X = "OKP", "Ed25519", b64.EncodeToString(k.ed)
	case k.ec != nil:
		raw, err := k.ec.Bytes()
		if err != nil {
			return jwk{}, errors.Join(ErrInvalidKey, err)
		}
		j.Kty, j.Crv, j.X, j.Y = "EC", "P-256", b64.EncodeToString(raw[1:33]), b64.EncodeToString(raw[33:])
	case k.rsa != nil:
		j.Kty, j.N, j.E = "RSA", b64.EncodeToString(k.rsa.N.Bytes()), b64.EncodeToString(big.NewInt(int64(k.rsa.E)).Bytes())
	default:
		return jwk{}, ErrNotPublishable
	}
	return j, nil
}

// EncodeJWKS returns the JWKS document {"keys": [...]} publishing vs. A symmetric key returns
// ErrNotPublishable and a repeated key id ErrDuplicateKeyID.
func EncodeJWKS(vs []Verifier) ([]byte, error) {
	if err := CheckKeyIDs(vs...); err != nil {
		return nil, err
	}
	keys := make([]jwk, 0, len(vs))
	for _, v := range vs {
		j, err := v.jwk()
		if err != nil {
			return nil, errors.Join(errors.New("kid "+v.KeyID()), err)
		}
		keys = append(keys, j)
	}
	return json.Marshal(struct {
		Keys []jwk `json:"keys"`
	}{keys})
}

// ParseJWKS parses a JWKS of public signing keys into verifiers. Keys outside egauth's scope are
// skipped, so a third-party identity provider's document can be consumed: a "use" other than
// "sig", a key type or curve other than OKP Ed25519, EC P-256 and RSA, or an "alg" egauth does not
// verify. A kept key without "alg" is bound to the only algorithm egauth verifies for its type
// (EdDSA, ES256, RS256), so each key id still maps to exactly one algorithm. ErrInvalidJWKS is
// returned when no key is kept, for private or symmetric key material anywhere in the document, an
// "alg" of another key type, a kept key without "kid", malformed or weak key parameters (RSA below
// 2048 bits), or a repeated key id.
func ParseJWKS(doc []byte) ([]Verifier, error) {
	if len(doc) > maxJWKSBytes {
		return nil, errors.Join(ErrInvalidJWKS, errors.New("document too large"))
	}
	var set jwkSet
	if err := json.Unmarshal(doc, &set); err != nil {
		return nil, errors.Join(ErrInvalidJWKS, err)
	}
	if len(set.Keys) == 0 || len(set.Keys) > maxJWKSKeys {
		return nil, errors.Join(ErrInvalidJWKS, errors.New("expected 1 to "+strconv.Itoa(maxJWKSKeys)+" keys"))
	}
	out := make([]Verifier, 0, len(set.Keys))
	for i, raw := range set.Keys {
		v, kept, err := parseJWK(raw)
		if err != nil {
			return nil, errors.Join(ErrInvalidJWKS, errors.New("key "+strconv.Itoa(i)), err)
		}
		if kept {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, errors.Join(ErrInvalidJWKS, errors.New("no EdDSA, ES256 or RS256 signing key"))
	}
	if err := CheckKeyIDs(out...); err != nil {
		return nil, errors.Join(ErrInvalidJWKS, err)
	}
	return out, nil
}

const algEd25519 = "Ed25519"

func jwkAlgorithm(j jwk) string {
	switch {
	case j.Kty == "OKP" && j.Crv == "Ed25519":
		return AlgEdDSA
	case j.Kty == "EC" && j.Crv == "P-256":
		return AlgES256
	case j.Kty == "RSA":
		return AlgRS256
	}
	return ""
}

func parseJWK(raw json.RawMessage) (Verifier, bool, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return Verifier{}, false, err
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := members[private]; ok {
			return Verifier{}, false, errors.New("private or symmetric key material")
		}
	}
	var j jwk
	if err := json.Unmarshal(raw, &j); err != nil {
		return Verifier{}, false, err
	}
	if j.Use != "" && j.Use != "sig" {
		return Verifier{}, false, nil
	}
	alg := jwkAlgorithm(j)
	switch {
	case alg == "":
		return Verifier{}, false, nil
	case j.Alg == "" || j.Alg == alg || (alg == AlgEdDSA && j.Alg == algEd25519):
	case j.Alg == AlgEdDSA || j.Alg == AlgES256 || j.Alg == AlgRS256 || j.Alg == AlgHS256:
		return Verifier{}, false, errors.New("alg " + j.Alg + " does not match kty/crv " + j.Kty + "/" + j.Crv)
	default:
		return Verifier{}, false, nil
	}
	if j.Kid == "" || len(j.Kid) > maxJWKKidLen {
		return Verifier{}, false, ErrInvalidKeyID
	}
	pk := &publicKey{alg: alg, kid: j.Kid}
	switch alg {
	case AlgEdDSA:
		x, err := b64.DecodeString(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return Verifier{}, false, errors.Join(errors.New("bad Ed25519 x"), err)
		}
		pk.ed = ed25519.PublicKey(x)
	case AlgES256:
		x, errX := b64.DecodeString(j.X)
		y, errY := b64.DecodeString(j.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return Verifier{}, false, errors.Join(errors.New("bad P-256 coordinates"), errX, errY)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{0x04}, x...), y...))
		if err != nil {
			return Verifier{}, false, err
		}
		pk.ec = pub
	default:
		pub, err := parseRSA(j)
		if err != nil {
			return Verifier{}, false, err
		}
		pk.rsa = pub
	}
	return Verifier{k: pk}, true, nil
}

func parseRSA(j jwk) (*rsa.PublicKey, error) {
	n, errN := b64.DecodeString(j.N)
	e, errE := b64.DecodeString(j.E)
	if errN != nil || errE != nil || len(e) == 0 || len(e) > 4 {
		return nil, errors.Join(errors.New("bad RSA modulus or exponent"), errN, errE)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if pub.N.BitLen() < minRSABits || pub.E < minRSAExponent || pub.E%2 == 0 {
		return nil, errors.New("RSA key below 2048 bits or with a weak exponent")
	}
	return pub, nil
}

// JWKSEndpoint is the location of a remote JWKS. It is a value spec: nothing is fetched here; the
// keys are fetched later through egauth's outbound client.
type JWKSEndpoint struct {
	u string
}

// JWKS validates rawURL as a JWKS location: absolute https, or http on a loopback host only, with
// no credentials and no fragment. Anything else returns ErrInvalidURL.
func JWKS(rawURL string) (JWKSEndpoint, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return JWKSEndpoint{}, errors.Join(ErrInvalidURL, err)
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(rawURL, " \t\r\n") {
		return JWKSEndpoint{}, ErrInvalidURL
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return JWKSEndpoint{}, errors.Join(ErrInvalidURL, errors.New("http is allowed on loopback only"))
		}
	default:
		return JWKSEndpoint{}, ErrInvalidURL
	}
	return JWKSEndpoint{u: u.String()}, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// URL returns the validated URL, or "" for the zero JWKSEndpoint.
func (e JWKSEndpoint) URL() string { return e.u }

// IsZero reports whether e was not built by JWKS.
func (e JWKSEndpoint) IsZero() bool { return e.u == "" }
