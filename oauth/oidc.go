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
	// defaultNegativeTTL is the duration an unknown kid is negatively cached (SEC-OAU-05).
	defaultNegativeTTL = 30 * time.Second
	// minRefreshInterval is the minimum cooldown duration between outbound JWKS refreshes (SEC-OAU-05).
	minRefreshInterval = 5 * time.Second
	// maxNegativeCacheEntries caps the negative cache size to prevent memory exhaustion (SEC-OAU-05).
	maxNegativeCacheEntries = 1000
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
	// document (<issuer>/.well-known/openid-configuration), where the trust chain is the exact
	// issuer match the discovery step enforces. When set, it is trusted developer configuration
	// and may point at a host other than the issuer (as Google does: accounts.google.com issues
	// tokens whose keys are served from www.googleapis.com), per the OIDC spec.
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
	// SEC-07: JWKSURL is an optional override of the discovered jwks_uri. It is trusted developer
	// configuration (not attacker input), so it is accepted as long as it is a valid endpoint URL.
	// The OIDC spec permits jwks_uri on a host other than the issuer (as Google does), so no
	// host-equality binding is imposed. When empty the jwks_uri is discovered from the issuer's
	// openid-configuration, where the trust chain is the exact issuer match on the document.
	jwksOverride := strings.TrimSpace(cfg.JWKSURL)
	if jwksOverride != "" {
		if err := validateOIDCEndpointURL(jwksOverride, cfg.AllowInsecureURLs); err != nil {
			return nil, fmt.Errorf("invalid JWKSURL: %w", err)
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
			url:                jwksOverride,
			issuer:             cfg.Issuer,
			allowInsecure:      cfg.AllowInsecureURLs,
			client:             client,
			ttl:                defaultJWKSCacheTTL,
			negativeTTL:        defaultNegativeTTL,
			minRefreshInterval: minRefreshInterval,
			now:                time.Now,
			negCache:           make(map[string]time.Time),
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
//
// To prevent amplification DoS attacks (SEC-OAU-05), unknown kids are negatively cached for
// negativeTTL, and remote JWKS refreshes are rate limited by minRefreshInterval cooldown.
//
// When url is empty it is resolved once, lazily, via OIDC discovery
// (<issuer>/.well-known/openid-configuration), whose document must claim the configured issuer
// exactly. An explicitly-provided url is treated as a pre-validated override.
type jwksCache struct {
	url                string // resolved (or override) jwks_uri; empty until discovery runs
	issuer             string // configured issuer, used to derive and bind the discovery document
	allowInsecure      bool   // dev-only: permit non-https discovery/JWKS URLs
	client             *http.Client
	ttl                time.Duration
	negativeTTL        time.Duration
	minRefreshInterval time.Duration
	now                func() time.Time

	mu          sync.RWMutex
	refreshMu   sync.Mutex
	keys        map[string]crypto.PublicKey
	exp         time.Time
	lastRefresh time.Time
	negCache    map[string]time.Time
}

func (c *jwksCache) timeNow() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *jwksCache) negTTL() time.Duration {
	if c.negativeTTL > 0 {
		return c.negativeTTL
	}
	return defaultNegativeTTL
}

func (c *jwksCache) minRefresh() time.Duration {
	if c.minRefreshInterval > 0 {
		return c.minRefreshInterval
	}
	return minRefreshInterval
}

func keyNotFoundError(kid string) error {
	if kid == "" {
		return fmt.Errorf("%w: id_token has no kid and the key set is ambiguous", ErrIDTokenInvalid)
	}
	return fmt.Errorf("%w: no JWKS key for kid %q", ErrIDTokenInvalid, kid)
}

func (c *jwksCache) isNegativelyCached(kid string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.negCache == nil {
		return false
	}
	exp, ok := c.negCache[kid]
	if !ok {
		return false
	}
	return c.timeNow().Before(exp)
}

func (c *jwksCache) setNegative(kid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.negCache == nil {
		c.negCache = make(map[string]time.Time)
	}
	now := c.timeNow()

	// Evict expired entries if we are at or above capacity.
	if len(c.negCache) >= maxNegativeCacheEntries {
		for k, exp := range c.negCache {
			if !now.Before(exp) {
				delete(c.negCache, k)
			}
		}
	}

	// If still at capacity, evict the oldest entry (earliest expiration time).
	if len(c.negCache) >= maxNegativeCacheEntries {
		var oldestKid string
		var oldestExp time.Time
		first := true
		for k, exp := range c.negCache {
			if first || exp.Before(oldestExp) {
				oldestKid = k
				oldestExp = exp
				first = false
			}
		}
		if !first {
			delete(c.negCache, oldestKid)
		}
	}

	c.negCache[kid] = now.Add(c.negTTL())
}

// publicKey returns the verification key for kid, fetching/refreshing the key set as needed.
func (c *jwksCache) publicKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	// 1. If kid is negatively cached and not expired, fail fast without fetching.
	if c.isNegativelyCached(kid) {
		return nil, keyNotFoundError(kid)
	}

	// 2. If key is already in memory cache, return it.
	if k, ok := c.cached(kid); ok {
		return k, nil
	}

	// 3. If refreshed too recently, rate limit and record kid in negative cache.
	c.mu.RLock()
	recentlyRefreshed := !c.lastRefresh.IsZero() && c.timeNow().Sub(c.lastRefresh) < c.minRefresh()
	c.mu.RUnlock()
	if recentlyRefreshed {
		c.setNegative(kid)
		return nil, keyNotFoundError(kid)
	}

	// 4. Acquire refresh lock to serialize outbound JWKS fetches.
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	// Double-check after acquiring refresh lock in case a concurrent fetch completed.
	if c.isNegativelyCached(kid) {
		return nil, keyNotFoundError(kid)
	}
	if k, ok := c.cached(kid); ok {
		return k, nil
	}
	c.mu.RLock()
	recentlyRefreshed = !c.lastRefresh.IsZero() && c.timeNow().Sub(c.lastRefresh) < c.minRefresh()
	c.mu.RUnlock()
	if recentlyRefreshed {
		c.setNegative(kid)
		return nil, keyNotFoundError(kid)
	}

	// 5. Fetch JWKS from remote endpoint.
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}

	c.mu.RLock()
	k, err := lookupKey(c.keys, kid)
	c.mu.RUnlock()
	if err != nil {
		c.setNegative(kid)
		return nil, keyNotFoundError(kid)
	}
	return k, nil
}

func (c *jwksCache) cached(kid string) (crypto.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.keys == nil || c.timeNow().After(c.exp) {
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
	now := c.timeNow()
	c.mu.Lock()
	c.keys = keys
	c.exp = now.Add(c.ttl)
	c.lastRefresh = now
	for k := range keys {
		delete(c.negCache, k)
	}
	c.mu.Unlock()
	return nil
}

// resolveURL returns the JWKS endpoint, performing OIDC discovery once and caching the result
// when no explicit url override was supplied. Discovery fetches the issuer's
// .well-known/openid-configuration over the configured client and verifies the document's own
// "issuer" matches the configured issuer exactly (per OIDC discovery) — that exact match, over
// a document fetched from the issuer's own origin, is the trust chain binding the jwks_uri.
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

// ErrJWKSHostMismatch is returned when an OIDC discovery document's own "issuer" field does not
// equal the configured issuer. The exact issuer match closes the trusted-issuer / attacker-keys
// confused-deputy class of attack; the jwks_uri it points to may legitimately live on another
// host (as Google's does).
var ErrJWKSHostMismatch = errors.New("oauth: JWKS source does not match issuer")
