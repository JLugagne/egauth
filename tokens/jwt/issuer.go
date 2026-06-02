package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// claimsWrapper wraps the standard JWT claims and our custom generic claims.
type claimsWrapper[C any] struct {
	jwt.RegisteredClaims
	TenantID string   `json:"tenant_id,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"` // OIDC auth_time (unix seconds), preserved across refresh
	Scopes   []string `json:"scopes,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	Custom   C        `json:"custom"`
}

// DefaultReuseGracePeriod is the window after a refresh token is consumed during which a
// replay of that same token is treated as benign concurrency (e.g. parallel tabs, link
// prefetch, or several sub-resource requests racing to rotate the same cookie) rather than
// theft. It mirrors the "refresh token reuse leeway" used by mainstream identity providers
// to avoid logging users out on ordinary request concurrency.
const DefaultReuseGracePeriod = 10 * time.Second

// Service provides JWT-based implementations of tokens.Issuer, tokens.Verifier and
// tokens.Rotator.
type Service[C any] struct {
	store          tokens.Store[C]
	claimsProvider tokens.ClaimsProvider[C]
	signingKey     []byte            // active key used to sign new access tokens
	signingKeyID   string            // "kid" stamped on new tokens ("" in legacy single-key mode)
	verifyKeys     map[string][]byte // kid -> key, for verifying kid-tagged tokens
	legacyKey      []byte            // key tried for a token carrying no kid (the configured SecretKey)
	issuer         string
	// expected audiences for the verify path; empty disables the aud check
	expectedAudiences []string
	accessTTL         time.Duration
	refreshTTL        time.Duration
	refreshLength     int
	apiKeyLength      int
	reuseGrace        time.Duration
	events            event.Sink
	now               func() time.Time
}

// SigningKey is one HMAC signing key in a rotation keyset. KeyID is a stable identifier emitted
// as the JWT "kid" header so a verifier can select the right key; Secret is the HS256 key.
type SigningKey struct {
	KeyID  string
	Secret string
}

// Config defines the configuration for the JWT Service.
type Config[C any] struct {
	Store  tokens.Store[C]
	Issuer string
	// ExpectedAudience gates the `aud` claim on the verify path. A token is accepted only if it
	// carries at least one of these audiences (any-of semantics). It guards against the
	// confused-deputy risk when a single symmetric (HS256) key is shared across services: a token
	// minted for audience A is then rejected by a service configured for audience B. Leaving it
	// empty disables audience checking entirely, preserving backward compatibility.
	ExpectedAudience []string
	// SecretKey is the HS256 signing key in single-key mode. When SigningKeys is also set it is
	// kept only as a "legacy" verification key for tokens minted (without a kid) before rotation
	// was enabled — it never signs new tokens.
	SecretKey string
	// SigningKeys is an optional rotation keyset. When non-empty, the key named by ActiveKeyID
	// signs new tokens (tagging them with its KeyID as the "kid" header) while EVERY key in the
	// set can verify — so a token signed by a now-retired key keeps validating until it expires
	// (overlapping-validity rollover). Roll keys by deploying the set with the new key added and
	// ActiveKeyID switched to it; once the longest-lived token signed by the old key has expired,
	// drop the old key from the set.
	SigningKeys []SigningKey
	// ActiveKeyID selects which SigningKeys entry signs new tokens. It defaults to the sole entry
	// when exactly one key is configured, and is required when several are.
	ActiveKeyID string
	// ClaimsProvider resolves fresh claims during refresh-token rotation. It is required
	// for Rotate; IssueTokenPair / IssueAPIKey do not need it.
	ClaimsProvider tokens.ClaimsProvider[C]
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	RefreshLength  int
	APIKeyLength   int
	// ReuseGracePeriod tunes refresh-token reuse detection. A replay of a consumed token
	// within this window is treated as benign concurrency (rejected without revoking the
	// family); a replay after it is treated as theft and revokes the whole family. The zero
	// value selects DefaultReuseGracePeriod; set a negative value for strict mode, where any
	// replay of a consumed token revokes the family.
	ReuseGracePeriod time.Duration
	// EventSink optionally receives security events emitted during rotation — refresh-token
	// reuse detection and token-family revocation (see the event package). Nil disables emission.
	EventSink event.Sink
	// Clock overrides the time source used for access-token TTL stamping and for exp/nbf
	// validation on the verify path (it is wired into the JWT parser too). Its primary use is
	// deterministic testing. The zero value defaults to time.Now.
	Clock func() time.Time
}

// MinSecretKeyLength is the recommended minimum HS256 signing-key length (bytes). A key
// shorter than the HMAC-SHA-256 output weakens the signature. Config.Validate enforces it.
const MinSecretKeyLength = 32

// Validate reports configuration that would make the issuer insecure or non-functional: an
// empty/too-short signing key (or keyset), an empty Issuer, or a non-positive Access/Refresh
// TTL. Production callers SHOULD call it at startup (it returns all problems joined). New itself
// only hard-fails configurations from which no coherent signer can be built, so test code may
// still construct an issuer with, e.g., a deliberately negative AccessTTL to exercise expiry.
func (cfg Config[C]) Validate() error {
	var errs []error

	if len(cfg.SigningKeys) == 0 {
		switch {
		case cfg.SecretKey == "":
			errs = append(errs, errors.New("jwt: SecretKey must not be empty"))
		case len(cfg.SecretKey) < MinSecretKeyLength:
			errs = append(errs, fmt.Errorf("jwt: SecretKey must be at least %d bytes for HS256", MinSecretKeyLength))
		}
	} else {
		seen := make(map[string]bool, len(cfg.SigningKeys))
		for i, k := range cfg.SigningKeys {
			switch {
			case k.KeyID == "":
				errs = append(errs, fmt.Errorf("jwt: SigningKeys[%d] must have a KeyID", i))
			case seen[k.KeyID]:
				errs = append(errs, fmt.Errorf("jwt: duplicate SigningKeys KeyID %q", k.KeyID))
			}
			seen[k.KeyID] = true
			if len(k.Secret) < MinSecretKeyLength {
				errs = append(errs, fmt.Errorf("jwt: SigningKeys[%q].Secret must be at least %d bytes for HS256", k.KeyID, MinSecretKeyLength))
			}
		}
		if cfg.ActiveKeyID == "" {
			if len(cfg.SigningKeys) > 1 {
				errs = append(errs, errors.New("jwt: ActiveKeyID is required when more than one SigningKeys is configured"))
			}
		} else if !seen[cfg.ActiveKeyID] {
			errs = append(errs, fmt.Errorf("jwt: ActiveKeyID %q is not present in SigningKeys", cfg.ActiveKeyID))
		}
		// A legacy SecretKey, if kept for the rollover window, should still be a strong key.
		if cfg.SecretKey != "" && len(cfg.SecretKey) < MinSecretKeyLength {
			errs = append(errs, fmt.Errorf("jwt: SecretKey must be at least %d bytes for HS256", MinSecretKeyLength))
		}
	}

	if cfg.Issuer == "" {
		errs = append(errs, errors.New("jwt: Issuer must not be empty"))
	}
	if cfg.AccessTTL <= 0 {
		errs = append(errs, errors.New("jwt: AccessTTL must be positive"))
	}
	if cfg.RefreshTTL <= 0 {
		errs = append(errs, errors.New("jwt: RefreshTTL must be positive"))
	}
	return errors.Join(errs...)
}

// resolveKeyset builds the signing/verification material from the config. It returns a structural
// error only when no coherent signer can be built (no key at all, a keyset entry missing its
// KeyID or Secret, a duplicate KeyID, or an unresolvable ActiveKeyID).
func resolveKeyset[C any](cfg Config[C]) (signKey []byte, signKeyID string, verify map[string][]byte, legacy []byte, err error) {
	verify = map[string][]byte{}
	if cfg.SecretKey != "" {
		legacy = []byte(cfg.SecretKey)
	}

	// Single-key (legacy) mode: sign without a kid; verify a kid-less token with the SecretKey.
	if len(cfg.SigningKeys) == 0 {
		if cfg.SecretKey == "" {
			return nil, "", nil, nil, errors.New("no signing key configured (set SecretKey or SigningKeys)")
		}
		return legacy, "", verify, legacy, nil
	}

	// Keyset mode: every key verifies; ActiveKeyID signs.
	seen := map[string]bool{}
	for _, k := range cfg.SigningKeys {
		if k.KeyID == "" {
			return nil, "", nil, nil, errors.New("every SigningKeys entry must have a KeyID")
		}
		if seen[k.KeyID] {
			return nil, "", nil, nil, fmt.Errorf("duplicate SigningKeys KeyID %q", k.KeyID)
		}
		if k.Secret == "" {
			return nil, "", nil, nil, fmt.Errorf("SigningKeys[%q] has an empty Secret", k.KeyID)
		}
		seen[k.KeyID] = true
		verify[k.KeyID] = []byte(k.Secret)
	}

	activeID := cfg.ActiveKeyID
	if activeID == "" {
		if len(cfg.SigningKeys) != 1 {
			return nil, "", nil, nil, errors.New("ActiveKeyID is required when more than one SigningKeys is configured")
		}
		activeID = cfg.SigningKeys[0].KeyID
	}
	sk, ok := verify[activeID]
	if !ok {
		return nil, "", nil, nil, fmt.Errorf("ActiveKeyID %q is not present in SigningKeys", activeID)
	}
	return sk, activeID, verify, legacy, nil
}

// New creates a new JWT Service. It panics on a configuration from which no coherent signer can
// be built (no signing key, or a malformed keyset) to fail fast instead of silently signing with
// an unusable key. For comprehensive startup validation call Config.Validate before New.
func New[C any](cfg Config[C]) *Service[C] {
	signKey, signKeyID, verifyKeys, legacyKey, err := resolveKeyset(cfg)
	if err != nil {
		panic("jwt: New: " + err.Error() + " (call Config.Validate to check configuration)")
	}
	if cfg.RefreshLength == 0 {
		cfg.RefreshLength = 32
	}
	if cfg.APIKeyLength == 0 {
		cfg.APIKeyLength = 32
	}
	if cfg.ReuseGracePeriod == 0 {
		cfg.ReuseGracePeriod = DefaultReuseGracePeriod
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}

	return &Service[C]{
		store:             cfg.Store,
		claimsProvider:    cfg.ClaimsProvider,
		signingKey:        signKey,
		signingKeyID:      signKeyID,
		verifyKeys:        verifyKeys,
		legacyKey:         legacyKey,
		issuer:            cfg.Issuer,
		expectedAudiences: cfg.ExpectedAudience,
		accessTTL:         cfg.AccessTTL,
		refreshTTL:        cfg.RefreshTTL,
		refreshLength:     cfg.RefreshLength,
		apiKeyLength:      cfg.APIKeyLength,
		reuseGrace:        cfg.ReuseGracePeriod,
		events:            cfg.EventSink,
		now:               cfg.Clock,
	}
}

// IssueTokenPair generates a new Access and Refresh token pair for the given claims,
// starting a fresh rotation family.
func (s *Service[C]) IssueTokenPair(ctx context.Context, claims tokens.Claims[C]) (*tokens.TokenPair[C], error) {
	return s.issuePair(ctx, claims, uuid.New(), true)
}

// issuePair signs an access JWT and mints an opaque refresh token, persisting the refresh
// token (hash only) within the given family. It is shared by initial issuance (new family)
// and rotation (existing family); initial reports which, so auth_time defaults to the issue
// time ONLY for a genuine fresh authentication and is never manufactured by a rotation.
func (s *Service[C]) issuePair(ctx context.Context, claims tokens.Claims[C], familyID uuid.UUID, initial bool) (*tokens.TokenPair[C], error) {
	now := s.now()
	accessExpiresAt := now.Add(s.accessTTL)
	if !claims.ExpiresAt.IsZero() {
		accessExpiresAt = claims.ExpiresAt
	}

	// auth_time anchors step-up freshness. For the INITIAL pair it defaults to the issue time
	// (the subject just authenticated); on rotation it is the family's preserved value, taken
	// verbatim — a rotation must NEVER manufacture a fresh auth_time (that would let a silent
	// refresh defeat the freshness gate). A legacy/zero auth_time therefore stays zero on
	// rotation, so FreshAuth fails closed and a re-authentication is correctly forced.
	authTime := claims.AuthTime
	if authTime.IsZero() && initial {
		authTime = now
	}
	var authTimeUnix int64
	if !authTime.IsZero() {
		authTimeUnix = authTime.Unix()
	}

	wrapper := claimsWrapper[C]{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   claims.Subject.String(),
			Audience:  claims.Audiences,
			ExpiresAt: jwt.NewNumericDate(accessExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		TenantID: claims.TenantID,
		AuthTime: authTimeUnix,
		Scopes:   claims.Scopes,
		Groups:   claims.Groups,
		Roles:    claims.Roles,
		AMR:      claims.AMR,
		Custom:   claims.Custom,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, wrapper)
	// Tag the token with the active key id so verifiers can select the right key during a
	// rollover. Legacy single-key mode leaves it empty, preserving the original (kid-less) format.
	if s.signingKeyID != "" {
		token.Header["kid"] = s.signingKeyID
	}
	accessTokenStr, err := token.SignedString(s.signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// Generate opaque refresh token.
	refreshBytes := make([]byte, s.refreshLength)
	if _, err := rand.Read(refreshBytes); err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	refreshTokenStr := base64.RawURLEncoding.EncodeToString(refreshBytes)
	refreshHash := tokens.HashToken(refreshTokenStr)
	refreshExpiresAt := now.Add(s.refreshTTL)

	rt := &tokens.RefreshToken{
		Hash:      refreshHash,
		FamilyID:  familyID,
		UserID:    claims.Subject,
		TenantID:  claims.TenantID,
		AuthTime:  authTime,
		ExpiresAt: refreshExpiresAt,
		CreatedAt: now,
	}

	if err := s.store.SaveRefreshToken(ctx, claims.TenantID, rt); err != nil {
		return nil, err
	}

	// Reflect the issuer-controlled access expiry and the resolved auth_time back into the
	// returned claims.
	claims.ExpiresAt = accessExpiresAt
	claims.AuthTime = authTime

	return &tokens.TokenPair[C]{
		AccessToken:           accessTokenStr,
		RefreshToken:          refreshTokenStr,
		RefreshTokenHash:      refreshHash,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshTokenExpiresAt: refreshExpiresAt,
		Claims:                claims,
	}, nil
}

// IssueAPIKey generates a new API Key with the specified prefix and claims.
func (s *Service[C]) IssueAPIKey(ctx context.Context, prefix string, claims tokens.Claims[C]) (*tokens.APIKey[C], error) {
	keyBytes := make([]byte, s.apiKeyLength)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate api key: %w", err)
	}

	tokenStr := prefix + base64.RawURLEncoding.EncodeToString(keyBytes)

	// Hash the token for storage.
	hashStr := tokens.HashToken(tokenStr)

	var expiresAt *time.Time
	if !claims.ExpiresAt.IsZero() {
		expiresAt = &claims.ExpiresAt
	}

	key := &tokens.APIKey[C]{
		ID:        uuid.New(),
		TenantID:  claims.TenantID,
		Prefix:    prefix,
		Token:     tokenStr,
		Hash:      hashStr,
		ExpiresAt: expiresAt,
		Claims:    claims,
	}

	if err := s.store.SaveAPIKey(ctx, claims.TenantID, key); err != nil {
		return nil, err
	}

	return key, nil
}

// verificationKey is the jwt.Keyfunc selecting the HMAC key for a token. It pins the signing
// method to HMAC (rejecting "none" and alg-confusion) and resolves the key by the "kid" header:
// a tagged token must match a key in the verification set; a token with NO kid header (legacy,
// or single-key mode) is verified with the legacy SecretKey. An unknown kid — or a present but
// malformed kid (non-string, or empty) — is rejected outright rather than falling back to the
// legacy key, so a present kid header can never be passed off as "kid-less".
func (s *Service[C]) verificationKey(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	// A present kid header must be a non-empty string and must name a known key. Only a token
	// that omits kid entirely may fall back to the legacy key.
	if rawKid, present := token.Header["kid"]; present {
		kid, ok := rawKid.(string)
		if !ok || kid == "" {
			return nil, errors.New("malformed kid header")
		}
		if key, ok := s.verifyKeys[kid]; ok {
			return key, nil
		}
		return nil, fmt.Errorf("unknown signing key id %q", kid)
	}
	if s.legacyKey != nil {
		return s.legacyKey, nil
	}
	return nil, errors.New("token has no kid and no legacy key is configured")
}

// VerifyAccessToken parses and validates an access token, returning its claims.
func (s *Service[C]) VerifyAccessToken(ctx context.Context, tokenStr string) (*tokens.Claims[C], error) {
	var wrapper claimsWrapper[C]

	// WithTimeFunc routes the library's exp/nbf validation through the same injected clock the
	// issuer stamps with, so the verify path is deterministic under a test clock (and honors a
	// custom clock in production). Without it golang-jwt would validate exp against time.Now().
	opts := []jwt.ParserOption{jwt.WithTimeFunc(s.now)}

	// Gate the "iss" claim only when an issuer is configured. WithIssuer makes the claim
	// mandatory and rejects a mismatch, so for issuer-less setups (legacy tokens carry no iss)
	// we must NOT add it — that would suddenly require an iss that was never stamped.
	if s.issuer != "" {
		opts = append(opts, jwt.WithIssuer(s.issuer))
	}

	// Gate the "aud" claim only when expected audiences are configured. golang-jwt v5's
	// WithAudience is variadic and, by default (expectAllAud=false), accepts a token whose aud
	// contains ANY of the listed values — exactly the any-of semantics we want, so a single
	// WithAudience(all...) call expresses "token is valid if it carries at least one of these".
	if len(s.expectedAudiences) > 0 {
		opts = append(opts, jwt.WithAudience(s.expectedAudiences...))
	}

	token, err := jwt.ParseWithClaims(tokenStr, &wrapper, s.verificationKey, opts...)

	if err != nil {
		// An expired token keeps the dedicated sentinel. An iss/aud mismatch is an
		// invalid-token condition (a confused-deputy attempt), NOT an expiry, so it maps to
		// ErrInvalidToken via the generic branch below.
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, tokens.ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, tokens.ErrInvalidToken
	}

	subject, err := uuid.Parse(wrapper.Subject)
	if err != nil {
		return nil, tokens.ErrInvalidClaims
	}

	claims := tokens.Claims[C]{
		Subject:   subject,
		TenantID:  wrapper.TenantID,
		IssuedAt:  wrapper.IssuedAt.Time,
		ExpiresAt: wrapper.ExpiresAt.Time,
		Audiences: wrapper.Audience,
		Scopes:    wrapper.Scopes,
		Groups:    wrapper.Groups,
		Roles:     wrapper.Roles,
		AMR:       wrapper.AMR,
		Custom:    wrapper.Custom,
	}
	if wrapper.AuthTime > 0 {
		claims.AuthTime = time.Unix(wrapper.AuthTime, 0).UTC()
	}

	return &claims, nil
}

// VerifyRefreshToken validates a refresh token against the store and returns its claims.
func (s *Service[C]) VerifyRefreshToken(ctx context.Context, token string) (*tokens.Claims[C], error) {
	hash := tokens.HashToken(token)

	// Since we don't store full claims for refresh tokens in this simple Store,
	// we just verify existence and return a minimal Claims object with the Subject.
	rt, err := s.store.FindRefreshToken(ctx, "", hash)
	if err != nil {
		return nil, err
	}

	if rt.ConsumedAt != nil {
		return nil, tokens.ErrRefreshTokenReused
	}

	if s.now().After(rt.ExpiresAt) {
		return nil, tokens.ErrTokenExpired
	}

	return &tokens.Claims[C]{
		Subject:   rt.UserID,
		TenantID:  rt.TenantID,
		ExpiresAt: rt.ExpiresAt,
	}, nil
}

// VerifyAPIKey validates an API key against the store and returns its claims.
func (s *Service[C]) VerifyAPIKey(ctx context.Context, key string) (*tokens.Claims[C], error) {
	hash := tokens.HashToken(key)

	apiKey, err := s.store.FindAPIKeyByHash(ctx, "", hash)
	if err != nil {
		return nil, err
	}

	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(s.now()) {
		return nil, tokens.ErrTokenExpired
	}

	return &apiKey.Claims, nil
}

// Verify interface compliance.
var (
	_ tokens.Issuer[any]   = (*Service[any])(nil)
	_ tokens.Verifier[any] = (*Service[any])(nil)
	_ tokens.Rotator[any]  = (*Service[any])(nil)
)

// Rotate consumes the presented refresh token and issues a fresh pair within the same
// family. A replayed (already-consumed) token triggers revocation of the whole family.
func (s *Service[C]) Rotate(ctx context.Context, tenantID string, refreshToken string) (*tokens.TokenPair[C], error) {
	if s.claimsProvider == nil {
		return nil, tokens.ErrNoClaimsProvider
	}

	hash := tokens.HashToken(refreshToken)

	rt, err := s.store.FindRefreshToken(ctx, tenantID, hash)
	if err != nil {
		return nil, err
	}

	// A consumed token was presented again. Within the reuse grace window this is treated
	// as benign concurrency (the legitimate client raced itself): the request is rejected
	// but the family is kept alive. Outside the window it is treated as theft — a stale
	// token resurfacing long after it was rotated away — and the whole family is revoked so
	// every descendant is invalidated. If the revocation itself fails we must NOT report a
	// clean reuse rejection (which the caller treats as "theft handled"); surface the
	// failure so the family is never silently assumed revoked. Wrapping keeps
	// errors.Is(…Reused) true for callers and cookie-clearing handlers.
	if rt.ConsumedAt != nil {
		if time.Since(*rt.ConsumedAt) > s.reuseGrace {
			if rerr := s.store.RevokeFamily(ctx, tenantID, rt.FamilyID); rerr != nil {
				return nil, fmt.Errorf("%w: family revocation failed: %v", tokens.ErrRefreshTokenReused, rerr)
			}
			event.Emit(ctx, s.events, event.Event{Type: event.TokenFamilyRevoked, UserID: rt.UserID.String(), TenantID: rt.TenantID, Reason: "refresh_reuse"})
			event.Emit(ctx, s.events, event.Event{Type: event.RefreshReuseDetected, UserID: rt.UserID.String(), TenantID: rt.TenantID, Reason: "after_grace"})
		} else {
			event.Emit(ctx, s.events, event.Event{Type: event.RefreshReuseDetected, UserID: rt.UserID.String(), TenantID: rt.TenantID, Reason: "within_grace"})
		}
		return nil, tokens.ErrRefreshTokenReused
	}

	if s.now().After(rt.ExpiresAt) {
		return nil, tokens.ErrTokenExpired
	}

	// Atomically consume (single-use). Losing this race means another in-flight request
	// rotated the SAME not-yet-consumed token first. That is benign concurrency (parallel
	// tabs, link prefetch, concurrent sub-resource loads), NOT theft — so we reject this
	// request WITHOUT revoking the family. A genuine replay is still caught above on the
	// next presentation, once ConsumedAt has been set by the completed rotation.
	if err := s.store.ConsumeRefreshToken(ctx, tenantID, hash); err != nil {
		return nil, err
	}

	// Resolve fresh claims (status, scopes, roles, ...) at rotation time rather than
	// trusting values frozen at login.
	claims, err := s.claimsProvider.ClaimsForUser(ctx, rt.UserID, rt.TenantID)
	if err != nil {
		return nil, err
	}

	// The tenant is immutable within a rotation family: keep the descendant in the SAME
	// partition used to find/consume/revoke, regardless of what the provider returns —
	// otherwise a divergent tenant would orphan the token out of reach of family
	// revocation. And the access-token lifetime is issuer-controlled on refresh: never
	// honor a provider-supplied expiry, which could extend a short-lived token unbounded.
	claims.TenantID = rt.TenantID
	claims.ExpiresAt = time.Time{}
	// Preserve the family's original authentication time: a silent refresh re-evaluates the
	// assurance level (AMR/scopes via the provider) but does NOT count as a fresh authentication,
	// so step-up freshness (WithMaxAuthAge) cannot be defeated by simply refreshing.
	claims.AuthTime = rt.AuthTime

	// Issue a new pair within the SAME family to preserve the rotation chain. initial=false:
	// a rotation never manufactures a fresh auth_time — claims.AuthTime (set above from the
	// family's preserved value, which may be zero for a legacy token) is taken verbatim.
	return s.issuePair(ctx, claims, rt.FamilyID, false)
}
