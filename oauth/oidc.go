package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrIDTokenInvalid is returned when an OIDC id_token fails validation (bad signature,
	// issuer, audience, expiry, missing claim, or an unresolvable signing key).
	ErrIDTokenInvalid = errors.New("oauth: id_token validation failed")
	// ErrNonceMismatch is returned when the id_token's nonce claim does not match the nonce
	// minted for this login attempt — the signal of a replayed or cross-bound id_token.
	ErrNonceMismatch = errors.New("oauth: id_token nonce mismatch")
)

// defaultAllowedAlgs are the asymmetric signing algorithms accepted for id_tokens by default.
// "none" and the HMAC family are deliberately excluded: accepting a symmetric alg while
// verifying against a JWKS public key is the classic RS256→HS256 algorithm-confusion attack.
var defaultAllowedAlgs = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

const (
	defaultOIDCLeeway   = time.Minute
	defaultJWKSCacheTTL = time.Hour
	// maxJWKSBytes bounds the JWKS response read.
	maxJWKSBytes = 1 << 20
	// maxJWKSKeys caps how many keys a JWKS document may declare. A document over this cap is
	// rejected outright (SEC-11): a hostile issuer could otherwise serve thousands of keys and
	// amplify CPU/memory during parsing and signature verification.
	maxJWKSKeys = 16
	// minRSABits and maxRSABits bound an RSA modulus to a sane range (SEC-11). Smaller moduli are
	// not securely usable; larger ones serve only to amplify verification cost.
	minRSABits = 2048
	maxRSABits = 8192
	// minRSAExponent and maxRSAExponent bound the RSA public exponent (SEC-11). It must be an odd
	// integer in [3, 2^24+1]; the conventional value is 65537.
	minRSAExponent = 3
	maxRSAExponent = (1 << 24) + 1
)

// OIDCConfig enables OpenID Connect id_token validation for a Provider (see WithOIDC). When set,
// Exchange validates the id_token returned by the token endpoint — its signature against the
// issuer's JWKS plus the iss / aud / exp / iat and nonce claims — and derives the UserInfo from
// the verified claims instead of trusting an access-token userinfo GET. This is what makes the
// flow true OIDC (cryptographically attested claims + nonce replay protection) rather than plain
// OAuth2.
type OIDCConfig struct {
	// Issuer is the expected "iss" claim. OIDC mandates an exact string comparison. Required.
	Issuer string
	// JWKSURL is an OPTIONAL override of the issuer's JSON Web Key Set endpoint. Leave it empty
	// to let the verifier discover the authoritative jwks_uri from the issuer's OIDC discovery
	// document (<issuer>/.well-known/openid-configuration) — this binds the verification keys to
	// the issuer and prevents a trusted issuer from being paired with an attacker-controlled key
	// set. When set, it is only accepted if its host equals the issuer host (defence in depth);
	// any other host is rejected.
	JWKSURL string
	// Audience is the expected "aud" claim. Defaults to the Provider's clientID when empty.
	Audience string
	// AllowedAlgs restricts the accepted id_token signing algorithms. Defaults to RS256/384/512
	// and ES256/384/512. "none" and HMAC algorithms are always rejected regardless of this list.
	AllowedAlgs []string
	// Leeway tolerates small clock skew when validating exp / iat (default 1 minute).
	Leeway time.Duration
	// ClaimsMapper maps the validated id_token claims to a UserInfo. Defaults to the standard
	// OIDC claims (sub → ProviderID, email, email_verified, name).
	ClaimsMapper func(claims map[string]any) (*UserInfo, error)
	// HTTPClient fetches the discovery document and the JWKS. Defaults to a client with a 10s
	// timeout. On the untrusted/dynamic path callers must inject oauth.SafeHTTPClient().
	HTTPClient *http.Client
	// AllowInsecureURLs opts INTO accepting non-https Issuer / JWKS / discovery URLs. It exists
	// only for local development against an http loopback IdP; it is secure-by-default (false) and
	// must never be set in production. When true the https requirement is skipped and, if no
	// HTTPClient is supplied, a plain http.Client is used (the SSRF-safe client blocks loopback at
	// dial time, so it cannot reach a dev IdP).
	AllowInsecureURLs bool
}

// oidcVerifier validates id_tokens for a configured issuer.
type oidcVerifier struct {
	issuer      string
	audience    string
	allowedAlgs []string
	leeway      time.Duration
	claimsMap   func(claims map[string]any) (*UserInfo, error)
	jwks        *jwksCache
}

// newOIDCVerifier builds a verifier from cfg, falling back to defaultAudience (the Provider's
// clientID) when no audience is configured. It validates the configuration eagerly so a
// misconfigured provider fails at construction rather than at the first callback.
func newOIDCVerifier(cfg OIDCConfig, defaultAudience string) (*oidcVerifier, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("OIDCConfig.Issuer is required")
	}
	// SEC-06: the issuer must be https by default. The dev-only AllowInsecureURLs opt-in relaxes
	// this for a local http loopback IdP.
	if err := validateOIDCEndpointURL(cfg.Issuer, cfg.AllowInsecureURLs); err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}
	// SEC-07: JWKSURL is now an optional override of the discovered jwks_uri. When supplied it is
	// accepted only if it is a valid endpoint URL AND its host matches the issuer host, so a
	// trusted issuer can never be bound to attacker-controlled keys; otherwise the jwks_uri is
	// discovered from the issuer's openid-configuration.
	jwksOverride := strings.TrimSpace(cfg.JWKSURL)
	if jwksOverride != "" {
		if err := validateOIDCEndpointURL(jwksOverride, cfg.AllowInsecureURLs); err != nil {
			return nil, fmt.Errorf("invalid JWKSURL: %w", err)
		}
		if !sameHost(jwksOverride, cfg.Issuer) {
			return nil, fmt.Errorf("%w: JWKSURL host does not match issuer host", ErrJWKSHostMismatch)
		}
	}
	audience := cfg.Audience
	if audience == "" {
		audience = defaultAudience
	}
	if audience == "" {
		return nil, errors.New("OIDCConfig.Audience is required when the provider has no clientID")
	}
	algs := cfg.AllowedAlgs
	if len(algs) == 0 {
		algs = defaultAllowedAlgs
	}
	leeway := cfg.Leeway
	if leeway <= 0 {
		leeway = defaultOIDCLeeway
	}
	mapper := cfg.ClaimsMapper
	if mapper == nil {
		mapper = defaultOIDCClaimsMapper
	}
	client := cfg.HTTPClient
	if client == nil {
		// In the dev/insecure path the SSRF-safe client (used on the untrusted dynamic path)
		// would block the loopback IdP at dial time, so fall back to a plain client. Production
		// callers on the dynamic path inject oauth.SafeHTTPClient() explicitly.
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &oidcVerifier{
		issuer:      cfg.Issuer,
		audience:    audience,
		allowedAlgs: algs,
		leeway:      leeway,
		claimsMap:   mapper,
		jwks: &jwksCache{
			url:           jwksOverride,
			issuer:        cfg.Issuer,
			allowInsecure: cfg.AllowInsecureURLs,
			client:        client,
			ttl:           defaultJWKSCacheTTL,
			now:           time.Now,
		},
	}, nil
}

// verify validates rawIDToken and returns the mapped UserInfo. expectedNonce is the nonce minted
// for this login attempt; it is mandatory (an empty expected nonce is itself a failure) so a
// replayed id_token bound to a different attempt is rejected.
func (v *oidcVerifier) verify(ctx context.Context, rawIDToken, expectedNonce string) (*UserInfo, error) {
	// Resolve the JWKS endpoint up front (running OIDC discovery on first use) so a host-binding
	// or discovery failure surfaces with its own sentinel rather than being swallowed by jwt's
	// non-unwrappable keyfunc error wrapper.
	if _, err := v.jwks.resolveURL(ctx); err != nil {
		return nil, err
	}
	keyFunc := func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.jwks.publicKey(ctx, kid)
	}
	token, err := jwt.Parse(rawIDToken, keyFunc,
		jwt.WithValidMethods(v.allowedAlgs),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(v.leeway),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIDTokenInvalid, err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected claims type", ErrIDTokenInvalid)
	}

	// Authorized-party (azp) checks per OIDC Core 3.1.3.7. jwt.WithAudience above only proves our
	// audience is CONTAINED in "aud"; for a token minted by the same issuer for another relying
	// party that also lists us, that is not enough (confused deputy). So: if azp is present it
	// MUST equal our audience, and a multi-audience token MUST carry such an azp.
	azp, _ := claims["azp"].(string)
	if azp != "" && subtle.ConstantTimeCompare([]byte(azp), []byte(v.audience)) != 1 {
		return nil, fmt.Errorf("%w: azp does not match audience", ErrIDTokenInvalid)
	}
	if len(audienceValues(claims["aud"])) > 1 && azp == "" {
		return nil, fmt.Errorf("%w: multiple audiences without an azp claim", ErrIDTokenInvalid)
	}

	// The nonce binds this id_token to the exact login attempt that minted it. Compare in
	// constant time; a missing or empty expected/actual nonce is a failure, never a pass.
	nonceClaim, _ := claims["nonce"].(string)
	if expectedNonce == "" || nonceClaim == "" ||
		subtle.ConstantTimeCompare([]byte(nonceClaim), []byte(expectedNonce)) != 1 {
		return nil, ErrNonceMismatch
	}

	info, err := v.claimsMap(map[string]any(claims))
	if err != nil {
		return nil, err
	}
	return info, nil
}

// audienceValues normalizes the "aud" claim (a string or an array of strings) into a slice,
// dropping empty entries.
func audienceValues(raw any) []string {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// defaultOIDCClaimsMapper maps the standard OIDC claims to a UserInfo.
func defaultOIDCClaimsMapper(claims map[string]any) (*UserInfo, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: missing sub claim", ErrIDTokenInvalid)
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	// email_verified may arrive as a bool or, from some providers, as the string "true".
	verified := false
	switch ev := claims["email_verified"].(type) {
	case bool:
		verified = ev
	case string:
		verified = ev == "true"
	}

	return &UserInfo{ProviderID: sub, Email: email, EmailVerified: verified, Name: name}, nil
}

// jwksCache fetches and caches an issuer's JSON Web Key Set, keyed by kid. It refetches on a
// cache miss (a kid it has not seen — i.e. key rotation) or when the TTL expires.
// jwksCache fetches and caches an issuer's JSON Web Key Set, keyed by kid. It refetches on a
// cache miss (a kid it has not seen — i.e. key rotation) or when the TTL expires.
//
// The JWKS endpoint is bound to the issuer: when url is empty it is resolved once, lazily, via
// OIDC discovery (<issuer>/.well-known/openid-configuration) and the resolved jwks_uri must
// belong to the issuer host. An explicitly-provided url is treated as a pre-validated override.
type jwksCache struct {
	url           string // resolved (or override) jwks_uri; empty until discovery runs
	issuer        string // configured issuer, used to derive and bind the discovery document
	allowInsecure bool   // dev-only: permit non-https discovery/JWKS URLs
	client        *http.Client
	ttl           time.Duration
	now           func() time.Time

	mu   sync.RWMutex
	keys map[string]crypto.PublicKey
	exp  time.Time
}

// publicKey returns the verification key for kid, fetching/refreshing the key set as needed.
func (c *jwksCache) publicKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if k, ok := c.cached(kid); ok {
		return k, nil
	}
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return lookupKey(c.keys, kid)
}

func (c *jwksCache) cached(kid string) (crypto.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.keys == nil || c.now().After(c.exp) {
		return nil, false
	}
	k, err := lookupKey(c.keys, kid)
	if err != nil {
		return nil, false
	}
	return k, true
}

func (c *jwksCache) refresh(ctx context.Context) error {
	jwksURL, err := c.resolveURL(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return fmt.Errorf("%w: building JWKS request: %v", ErrIDTokenInvalid, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: fetching JWKS: %v", ErrIDTokenInvalid, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: JWKS endpoint status %d", ErrIDTokenInvalid, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return fmt.Errorf("%w: reading JWKS: %v", ErrIDTokenInvalid, err)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.keys = keys
	c.exp = c.now().Add(c.ttl)
	c.mu.Unlock()
	return nil
}

// resolveURL returns the JWKS endpoint, performing OIDC discovery once and caching the result
// when no explicit url override was supplied. Discovery fetches the issuer's
// .well-known/openid-configuration over the configured client, verifies the document's own
// "issuer" matches the configured issuer exactly (per OIDC discovery), and binds the resolved
// jwks_uri to the issuer host so a trusted issuer can never be paired with foreign keys.
func (c *jwksCache) resolveURL(ctx context.Context) (string, error) {
	c.mu.RLock()
	cached := c.url
	c.mu.RUnlock()
	if cached != "" {
		return cached, nil
	}
	jwksURL, err := discoverJWKSURL(ctx, c.client, c.issuer, c.allowInsecure)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.url = jwksURL
	c.mu.Unlock()
	return jwksURL, nil
}

// lookupKey resolves kid in keys. An empty kid is accepted only when the set holds exactly one
// key (an id_token without a kid is unambiguous then).
func lookupKey(keys map[string]crypto.PublicKey, kid string) (crypto.PublicKey, error) {
	if kid == "" {
		if len(keys) == 1 {
			for _, k := range keys {
				return k, nil
			}
		}
		return nil, fmt.Errorf("%w: id_token has no kid and the key set is ambiguous", ErrIDTokenInvalid)
	}
	k, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: no JWKS key for kid %q", ErrIDTokenInvalid, kid)
	}
	return k, nil
}

// jwk is a single JSON Web Key (the subset egauth understands: RSA and EC signing keys).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseJWKS parses a JWKS document into a kid→public-key map, skipping encryption keys and any
// key it cannot construct. It errors only if no usable signing key remains.
func parseJWKS(data []byte) (map[string]crypto.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("%w: decoding JWKS: %v", ErrIDTokenInvalid, err)
	}
	// Reject documents declaring more keys than maxJWKSKeys before constructing any of them, so a
	// hostile issuer cannot force us to attempt building thousands of keys (SEC-11).
	if len(set.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("%w: JWKS declares %d keys, over the %d-key cap", ErrIDTokenInvalid, len(set.Keys), maxJWKSKeys)
	}
	out := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Use == "enc" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no usable signing keys in JWKS", ErrIDTokenInvalid)
	}
	return out, nil
}

// publicKey constructs the crypto public key represented by the JWK.
func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := decodeBigInt(k.N)
		if err != nil {
			return nil, err
		}
		// Bound the modulus to a sane size (SEC-11): below minRSABits it is not securely usable,
		// above maxRSABits it only serves to amplify verification cost.
		if bits := n.BitLen(); bits < minRSABits || bits > maxRSABits {
			return nil, fmt.Errorf("%w: RSA modulus %d bits out of range [%d, %d]", ErrIDTokenInvalid, bits, minRSABits, maxRSABits)
		}
		eb, err := decodeBase64URL(k.E)
		if err != nil {
			return nil, err
		}
		// Reject an oversized exponent before narrowing to int64 (avoiding truncation), then enforce
		// the conventional odd-exponent range [3, 2^24+1] (SEC-11); the common value is 65537.
		ebig := new(big.Int).SetBytes(eb)
		if ebig.BitLen() > 25 {
			return nil, fmt.Errorf("%w: RSA exponent too large", ErrIDTokenInvalid)
		}
		e := ebig.Int64()
		if e < minRSAExponent || e > maxRSAExponent || e%2 == 0 {
			return nil, fmt.Errorf("%w: invalid RSA exponent %d", ErrIDTokenInvalid, e)
		}
		return &rsa.PublicKey{N: n, E: int(e)}, nil
	case "EC":
		curve, err := curveForJWK(k.Crv)
		if err != nil {
			return nil, err
		}
		xb, err := decodeBase64URL(k.X)
		if err != nil {
			return nil, err
		}
		yb, err := decodeBase64URL(k.Y)
		if err != nil {
			return nil, err
		}
		// Reassemble the SEC1 uncompressed point (0x04 || X || Y, each coordinate left-padded to
		// the curve's field size) and parse it with the modern API, which also verifies the point
		// is actually on the curve (rejecting invalid-curve keys) — unlike assigning the raw
		// X/Y fields directly (deprecated since Go 1.25).
		size := (curve.Params().BitSize + 7) / 8
		if len(xb) > size || len(yb) > size {
			return nil, fmt.Errorf("%w: EC coordinate exceeds curve size", ErrIDTokenInvalid)
		}
		point := make([]byte, 1+2*size)
		point[0] = 4
		copy(point[1+size-len(xb):1+size], xb)
		copy(point[1+2*size-len(yb):], yb)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid EC public key: %v", ErrIDTokenInvalid, err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("%w: unsupported key type %q", ErrIDTokenInvalid, k.Kty)
	}
}

func curveForJWK(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: unsupported EC curve %q", ErrIDTokenInvalid, crv)
	}
}

func decodeBase64URL(s string) ([]byte, error) {
	// JWK members are base64url without padding, but tolerate padded input defensively.
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("%w: decoding key material: %v", ErrIDTokenInvalid, err)
	}
	return b, nil
}

func decodeBigInt(s string) (*big.Int, error) {
	b, err := decodeBase64URL(s)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: empty key parameter", ErrIDTokenInvalid)
	}
	return new(big.Int).SetBytes(b), nil
}

// ErrJWKSHostMismatch is returned when an OIDC JWKS source does not belong to the issuer:
// either an explicitly-supplied JWKSURL whose host differs from the issuer host, or a
// discovery document whose jwks_uri host (or its own "issuer" field) does not match the
// configured issuer. Binding the keys to the issuer closes the trusted-issuer / attacker-keys
// confused-deputy class of attack.
var ErrJWKSHostMismatch = errors.New("oauth: JWKS source does not match issuer")
