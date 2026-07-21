package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// claimsWrapper wraps the standard JWT claims and our custom generic claims.
type claimsWrapper[C any] struct {
	jwt.RegisteredClaims
	TenantID string `json:"tenant_id,omitempty"`
	AuthTime int64  `json:"auth_time,omitempty"` // OIDC auth_time (unix seconds), preserved across refresh
	// Kind is the principal classification stamped at issuance for API-key-backed access tokens.
	// It is omitted for plain interactive sessions (zero value round-trips as ""; the middleware
	// actorFromClaims normalises "" to egauth.User so the WithRequiredKind gate behaves correctly).
	Kind               egauth.PrincipalKind `json:"kind,omitempty"`
	Scopes             []string             `json:"scopes,omitempty"`
	Groups             []string             `json:"groups,omitempty"`
	Roles              []string             `json:"roles,omitempty"`
	AMR                []string             `json:"amr,omitempty"`
	MustChangePassword bool                 `json:"must_change_password,omitempty"`
	Custom             C                    `json:"custom"`
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
	active         Signer            // signs new tokens on the static path (nil only when no static signer)
	signingKeyID   string            // "kid" stamped on new tokens ("" in legacy single-key mode)
	verifySigners  map[string]Signer // kid -> signer, for verifying kid-tagged tokens
	legacy         Signer            // signer tried for a token carrying no kid (the configured SecretKey); may be nil
	// keyStore, when non-nil, resolves the signing/verification keyset per tenant, overriding the
	// static signers above. Nil keeps the static single-keyset (zero-config) mode.
	keyStore KeyStore
	issuer   string
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
	// Signers, when non-empty, is the pluggable signer set (HMAC or asymmetric). It supersedes
	// SecretKey/SigningKeys for signing and verification: the signer named by ActiveKeyID signs new
	// tokens (stamping its KeyID as "kid"); every signer verifies. A non-empty SecretKey alongside
	// Signers is kept as a kid-less legacy VERIFY-only HMAC key. SigningKeys MUST NOT be combined with
	// Signers.
	Signers []Signer
	// KeyStore optionally provides per-tenant signing material, enabling per-tenant cryptographic
	// isolation: when set, the Service resolves each tenant's keyset through it instead of using the
	// static SecretKey/SigningKeys above. The static keyset still serves the single-tenant partition
	// ("") and is the fallback when a tenant is unknown to the KeyStore. Leaving it nil keeps the
	// zero-config single-keyset mode. See github.com/JLugagne/egauth/keystore.
	KeyStore KeyStore
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
	// InsecureAllowWeakKey suppresses the MinSecretKeyLength enforcement inside New. It must
	// only be set in test code that intentionally uses short keys (e.g. to exercise edge-case
	// paths without needing a 32-byte secret). Production callers must never set this field —
	// doing so removes the brute-force resistance guarantee for HS256.
	InsecureAllowWeakKey bool
}

// MinSecretKeyLength is the recommended minimum HS256 signing-key length (bytes). A key
// shorter than the HMAC-SHA-256 output weakens the signature. Config.Validate enforces it.
const MinSecretKeyLength = 32

// MinTokenLength is the minimum allowed length for opaque tokens (refresh tokens and API
// keys). Values shorter than this produce tokens with insufficient entropy and are
// online-brute-forceable. Config.Validate and New both enforce this limit.
const MinTokenLength = 16

// Validate reports configuration that would make the issuer insecure or non-functional: an
// empty/too-short signing key (or keyset), an empty Issuer, or a non-positive Access/Refresh
// TTL. Production callers SHOULD call it at startup (it returns all problems joined). New itself
// only hard-fails configurations from which no coherent signer can be built, so test code may
// still construct an issuer with, e.g., a deliberately negative AccessTTL to exercise expiry.
func (cfg Config[C]) Validate() error {
	var errs []error

	// Fail fast on missing mandatory dependencies.
	if cfg.Store == nil {
		errs = append(errs, errors.New("jwt: Store must not be nil"))
	}
	if cfg.ClaimsProvider == nil {
		errs = append(errs, errors.New("jwt: ClaimsProvider must not be nil"))
	}

	switch {
	case len(cfg.Signers) > 0:
		if len(cfg.SigningKeys) > 0 {
			errs = append(errs, errors.New("jwt: Signers must not be combined with SigningKeys"))
		}
		seen := make(map[string]bool, len(cfg.Signers))
		for i, sg := range cfg.Signers {
			kid := sg.KeyID()
			switch {
			case kid == "":
				errs = append(errs, fmt.Errorf("jwt: Signers[%d] must have a non-empty KeyID", i))
			case seen[kid]:
				errs = append(errs, fmt.Errorf("jwt: duplicate Signers KeyID %q", kid))
			}
			seen[kid] = true
		}
		if cfg.ActiveKeyID == "" {
			if len(cfg.Signers) > 1 {
				errs = append(errs, errors.New("jwt: ActiveKeyID is required when more than one Signers is configured"))
			}
		} else if !seen[cfg.ActiveKeyID] {
			errs = append(errs, fmt.Errorf("jwt: ActiveKeyID %q is not present in Signers", cfg.ActiveKeyID))
		}
		// A legacy SecretKey kept for kid-less rollover must still be a strong HMAC key.
		if cfg.SecretKey != "" && len(cfg.SecretKey) < MinSecretKeyLength {
			errs = append(errs, fmt.Errorf("jwt: SecretKey must be at least %d bytes for HS256", MinSecretKeyLength))
		}
	case len(cfg.SigningKeys) == 0:
		switch {
		case cfg.SecretKey == "":
			errs = append(errs, errors.New("jwt: SecretKey must not be empty"))
		case len(cfg.SecretKey) < MinSecretKeyLength:
			errs = append(errs, fmt.Errorf("jwt: SecretKey must be at least %d bytes for HS256", MinSecretKeyLength))
		}
	default:
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
	// A non-zero RefreshLength or APIKeyLength below MinTokenLength yields guessable tokens.
	// Zero means "use the default (32)" and is accepted here; New substitutes the safe default.
	if cfg.RefreshLength != 0 && cfg.RefreshLength < MinTokenLength {
		errs = append(errs, fmt.Errorf("jwt: RefreshLength must be 0 (use default) or at least %d bytes", MinTokenLength))
	}
	if cfg.APIKeyLength != 0 && cfg.APIKeyLength < MinTokenLength {
		errs = append(errs, fmt.Errorf("jwt: APIKeyLength must be 0 (use default) or at least %d bytes", MinTokenLength))
	}
	return errors.Join(errs...)
}

// resolveKeyset builds the signing/verification signers from the config. It returns the active
// signer (signs new static-path tokens), the verify set keyed by kid, and an optional kid-less
// legacy signer. It returns a structural error only when no coherent signer can be built (no key at
// all, a malformed entry, a duplicate KeyID, an unresolvable ActiveKeyID, or Signers combined with
// SigningKeys).
func resolveKeyset[C any](cfg Config[C]) (active Signer, verify map[string]Signer, legacy Signer, err error) {
	verify = map[string]Signer{}

	// A non-empty SecretKey is always built as the kid-less legacy HMAC signer (verify-only when
	// Signers/SigningKeys drive signing; the active signer in single-key mode). This preserves the
	// weak-key error wording surfaced by New.
	if cfg.SecretKey != "" {
		legacy, err = newHMACSignerAllowWeak("", []byte(cfg.SecretKey), cfg.InsecureAllowWeakKey)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// Signers path: pluggable signer set supersedes SecretKey/SigningKeys for signing/verification.
	if len(cfg.Signers) > 0 {
		if len(cfg.SigningKeys) > 0 {
			return nil, nil, nil, errors.New("jwt: Signers must not be combined with SigningKeys")
		}
		for _, sg := range cfg.Signers {
			kid := sg.KeyID()
			if kid == "" {
				return nil, nil, nil, errors.New("every Signers entry must have a non-empty KeyID")
			}
			if _, dup := verify[kid]; dup {
				return nil, nil, nil, fmt.Errorf("duplicate Signers KeyID %q", kid)
			}
			verify[kid] = sg
		}
		activeID := cfg.ActiveKeyID
		if activeID == "" {
			if len(cfg.Signers) != 1 {
				return nil, nil, nil, errors.New("ActiveKeyID is required when more than one Signers is configured")
			}
			activeID = cfg.Signers[0].KeyID()
		}
		a, ok := verify[activeID]
		if !ok {
			return nil, nil, nil, fmt.Errorf("ActiveKeyID %q is not present in Signers", activeID)
		}
		return a, verify, legacy, nil
	}

	// Single-key (legacy) mode: sign without a kid; verify a kid-less token with the SecretKey.
	if len(cfg.SigningKeys) == 0 {
		if cfg.SecretKey == "" {
			return nil, nil, nil, errors.New("no signing key configured (set SecretKey, SigningKeys or Signers)")
		}
		return legacy, verify, legacy, nil
	}

	// Keyset mode: every key verifies; ActiveKeyID signs. Each key becomes an HMAC signer.
	seen := map[string]bool{}
	for _, k := range cfg.SigningKeys {
		if k.KeyID == "" {
			return nil, nil, nil, errors.New("every SigningKeys entry must have a KeyID")
		}
		if seen[k.KeyID] {
			return nil, nil, nil, fmt.Errorf("duplicate SigningKeys KeyID %q", k.KeyID)
		}
		if k.Secret == "" {
			return nil, nil, nil, fmt.Errorf("SigningKeys[%q] has an empty Secret", k.KeyID)
		}
		sig, serr := newHMACSignerAllowWeak(k.KeyID, []byte(k.Secret), cfg.InsecureAllowWeakKey)
		if serr != nil {
			return nil, nil, nil, fmt.Errorf("SigningKeys[%q]: %w", k.KeyID, serr)
		}
		seen[k.KeyID] = true
		verify[k.KeyID] = sig
	}

	activeID := cfg.ActiveKeyID
	if activeID == "" {
		if len(cfg.SigningKeys) != 1 {
			return nil, nil, nil, errors.New("ActiveKeyID is required when more than one SigningKeys is configured")
		}
		activeID = cfg.SigningKeys[0].KeyID
	}
	a, ok := verify[activeID]
	if !ok {
		return nil, nil, nil, fmt.Errorf("ActiveKeyID %q is not present in SigningKeys", activeID)
	}
	return a, verify, legacy, nil
}

// New creates a new JWT Service. It panics on a configuration from which no coherent signer can
// be built: no signing key, a malformed keyset, any key shorter than MinSecretKeyLength, or a
// RefreshLength/APIKeyLength below MinTokenLength.
// The MinSecretKeyLength check can be suppressed via Config.InsecureAllowWeakKey — that field
// exists exclusively for test code that needs short keys; production callers must never set it.
// For comprehensive startup validation (TTLs, Issuer, etc.) call Config.Validate before New.
func New[C any](cfg Config[C]) *Service[C] {
	// Fail fast at startup rather than with a nil-pointer panic deep in a request,
	// matching the convention of identity.NewService, sessions.NewService, otp.NewService
	// and mfa.NewService.
	if cfg.Store == nil {
		panic("jwt: New requires a non-nil Store")
	}
	active, verifySigners, legacy, err := resolveKeyset(cfg)
	if err != nil {
		panic("jwt: New: " + err.Error() + " (call Config.Validate to check configuration)")
	}
	signKeyID := ""
	if active != nil {
		signKeyID = active.KeyID()
	}
	if cfg.RefreshLength == 0 {
		cfg.RefreshLength = 32
	}
	if cfg.APIKeyLength == 0 {
		cfg.APIKeyLength = 32
	}
	// Reject sub-minimum token lengths after the zero-means-default substitution above,
	// so any explicitly low positive value is caught here (not silently accepted).
	if cfg.RefreshLength < MinTokenLength {
		panic(fmt.Sprintf("jwt: New: RefreshLength %d is below MinTokenLength %d — tokens would be guessable (call Config.Validate to check configuration)", cfg.RefreshLength, MinTokenLength))
	}
	if cfg.APIKeyLength < MinTokenLength {
		panic(fmt.Sprintf("jwt: New: APIKeyLength %d is below MinTokenLength %d — tokens would be guessable (call Config.Validate to check configuration)", cfg.APIKeyLength, MinTokenLength))
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
		active:            active,
		signingKeyID:      signKeyID,
		verifySigners:     verifySigners,
		legacy:            legacy,
		keyStore:          cfg.KeyStore,
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
	return s.issuePair(ctx, claims, uuid.Must(uuid.NewV7()), true)
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
			ID:        uuid.Must(uuid.NewV7()).String(),
		},
		TenantID:           claims.TenantID,
		AuthTime:           authTimeUnix,
		Kind:               claims.Kind,
		Scopes:             claims.Scopes,
		Groups:             claims.Groups,
		Roles:              claims.Roles,
		AMR:                claims.AMR,
		MustChangePassword: claims.MustChangePassword,
		Custom:             claims.Custom,
	}

	// Resolve the signing key for this tenant. With a KeyStore configured this is the tenant's
	// active key (per-tenant cryptographic isolation); otherwise it is the static keyset.
	signer, err := s.resolveSigningKey(ctx, claims.TenantID)
	if err != nil {
		return nil, err
	}
	token := jwt.NewWithClaims(signer.Method(), wrapper)
	// Tag the token with the active key id so verifiers can select the right key during a
	// rollover. Legacy single-key mode leaves it empty, preserving the original (kid-less) format.
	if kid := signer.KeyID(); kid != "" {
		token.Header["kid"] = kid
	}
	accessTokenStr, err := token.SignedString(signer.SignKey())
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
		Hash:               refreshHash,
		FamilyID:           familyID,
		UserID:             claims.Subject,
		TenantID:           claims.TenantID,
		AuthTime:           authTime,
		MustChangePassword: claims.MustChangePassword,
		ExpiresAt:          refreshExpiresAt,
		CreatedAt:          now,
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

// ErrPATSubjectMismatch is returned by IssueAPIKey when a KeyTypePAT is issued with a
// Claims.Subject that names a different user than createdBy. A PAT acts as its creator, and its
// revocation is scoped by CreatedBy, so the two must agree (leave Subject unset to default it).
var ErrPATSubjectMismatch = errors.New("jwt: a PAT's Claims.Subject must equal createdBy")

// IssueAPIKey generates a new API key of the given type, attributed to the human user
// createdBy, carrying the authority (scopes/roles/audiences) supplied on claims verbatim.
//
// The caller is fully responsible for the key's authority: the issuer NEVER reads or copies
// the creating user's stored roles/scopes. Whatever scopes a leaked key can exercise are
// exactly the ones passed here, so callers should grant the narrowest set required.
//
// Claims.Subject is set per type and reflects what the key IS:
//   - KeyTypePAT: the key acts on behalf of a human, so Subject is the user as supplied by the
//     caller on claims.Subject (left untouched).
//   - KeyTypeService: the key is a machine identity decoupled from any human, so Subject is
//     overwritten with the newly generated key ID; createdBy remains the only link back to the
//     human who minted it (recorded on APIKey.CreatedBy, not on the subject).
func (s *Service[C]) IssueAPIKey(ctx context.Context, prefix string, keyType tokens.KeyType, createdBy uuid.UUID, claims tokens.Claims[C]) (*tokens.APIKey[C], error) {
	keyBytes := make([]byte, s.apiKeyLength)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate api key: %w", err)
	}

	tokenStr := prefix + base64.RawURLEncoding.EncodeToString(keyBytes)

	// Hash the token for storage.
	hashStr := tokens.HashToken(tokenStr)

	keyID := uuid.Must(uuid.NewV7())

	// A Service token is a machine identity decoupled from any human: its subject is its own key
	// ID, not the creator. A PAT acts on behalf of a human and MUST act as its creator: its
	// subject is pinned to createdBy so that revocation scoped by CreatedBy (DisableUser →
	// RevokeAllAPIKeysForUser) always severs it. A caller-supplied Subject naming a different user
	// is rejected rather than silently honored (that divergence would let a PAT outlive the
	// disable of the user it acts as). The authority on claims (scopes/roles/audiences) is used as
	// given for either type — never inflated from the creator's stored roles.
	if keyType == tokens.KeyTypeService {
		claims.Subject = keyID
	} else {
		if claims.Subject != uuid.Nil && claims.Subject != createdBy {
			return nil, ErrPATSubjectMismatch
		}
		claims.Subject = createdBy
	}

	var expiresAt *time.Time
	if !claims.ExpiresAt.IsZero() {
		expiresAt = &claims.ExpiresAt
	}

	key := &tokens.APIKey[C]{
		ID:        keyID,
		TenantID:  claims.TenantID,
		Prefix:    prefix,
		Token:     tokenStr,
		Hash:      hashStr,
		ExpiresAt: expiresAt,
		Type:      keyType,
		CreatedBy: createdBy,
		Claims:    claims,
	}

	if err := s.store.SaveAPIKey(ctx, claims.TenantID, key); err != nil {
		return nil, err
	}

	// Emit api_key.created. Attrs carry type and created_by for observability; the clear-text
	// token and its hash are intentionally excluded (events carry no secrets).
	event.Emit(ctx, s.events, event.Event{
		Type:     event.APIKeyCreated,
		TenantID: key.TenantID,
		UserID:   key.CreatedBy.String(),
		Attrs: map[string]any{
			"key_type":   string(key.Type),
			"created_by": key.CreatedBy.String(),
		},
	})

	return key, nil
}

// verificationKey is the jwt.Keyfunc selecting the verification key for a token. It resolves the
// Signer for the token's "kid" (or the legacy kid-less signer) BEFORE consulting the alg, then
// pins token.Method.Alg() to that signer's algorithm. Resolving the signer first is the
// alg-confusion defense: a token claiming alg:HS256 against a kid that maps to an RSA signer is
// rejected (HS256 != RS256), and "none" never matches any signer's alg. A present but malformed
// kid (non-string or empty) is rejected outright rather than falling back to the legacy key.
func (s *Service[C]) verificationKey(token *jwt.Token) (any, error) {
	signer, err := s.resolveVerifySigner(token)
	if err != nil {
		return nil, err
	}
	if token.Method.Alg() != signer.Method().Alg() {
		return nil, fmt.Errorf("unexpected signing method %q for key %q", token.Method.Alg(), signer.KeyID())
	}
	return signer.VerifyKey(), nil
}

// resolveVerifySigner selects the static-path Signer for a token: by its "kid" header when present
// (which must be a non-empty string naming a known signer), or the legacy kid-less signer when the
// header is absent. A present kid can never be passed off as "kid-less".
func (s *Service[C]) resolveVerifySigner(token *jwt.Token) (Signer, error) {
	if rawKid, present := token.Header["kid"]; present {
		kid, ok := rawKid.(string)
		if !ok || kid == "" {
			return nil, errors.New("malformed kid header")
		}
		if signer, ok := s.verifySigners[kid]; ok {
			return signer, nil
		}
		return nil, fmt.Errorf("unknown signing key id %q", kid)
	}
	if s.legacy != nil {
		return s.legacy, nil
	}
	return nil, errors.New("token has no kid and no legacy key is configured")
}

// verifyAccessToken runs the full signature/expiry/issuer/audience validation of an access
// token and returns its claims WITHOUT any tenant binding. It is the shared core used by the
// public VerifyAccessToken (single-tenant) and VerifyAccessTokenForTenant (which adds the tenant
// comparison). It is unexported precisely so the tenant binding cannot be bypassed by callers.
func (s *Service[C]) verifyAccessToken(ctx context.Context, tenantID string, tokenStr string) (*tokens.Claims[C], error) {
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

	// Select the verification keyfunc: per-tenant via the KeyStore when configured, else the
	// static keyset. The per-tenant keyfunc only consults tenantID's keys, so a token signed for
	// another tenant cannot verify here (cross-tenant isolation on the verify path).
	keyFunc := s.verificationKey
	if s.keyStore != nil {
		keyFunc = s.tenantKeyFunc(ctx, tenantID)
	}
	token, err := jwt.ParseWithClaims(tokenStr, &wrapper, keyFunc, opts...)

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
		Subject:            subject,
		TenantID:           wrapper.TenantID,
		Kind:               wrapper.Kind,
		IssuedAt:           wrapper.IssuedAt.Time,
		ExpiresAt:          wrapper.ExpiresAt.Time,
		Audiences:          wrapper.Audience,
		Scopes:             wrapper.Scopes,
		Groups:             wrapper.Groups,
		Roles:              wrapper.Roles,
		AMR:                wrapper.AMR,
		MustChangePassword: wrapper.MustChangePassword,
		Custom:             wrapper.Custom,
	}
	if wrapper.AuthTime > 0 {
		claims.AuthTime = time.Unix(wrapper.AuthTime, 0).UTC()
	}

	return &claims, nil
}

// VerifyRefreshToken validates a refresh token against the store and returns its claims.
// tenantID scopes the store lookup to a single tenant's partition: a token saved under a
// real tenant resolves only when the matching tenantID is passed, and verification fails
// closed (not-found) otherwise. Single-tenant callers pass "" (the default partition).
func (s *Service[C]) VerifyRefreshToken(ctx context.Context, tenantID string, token string) (*tokens.Claims[C], error) {
	hash := tokens.HashToken(token)

	// Since we don't store full claims for refresh tokens in this simple Store,
	// we just verify existence and return a minimal Claims object with the Subject.
	rt, err := s.store.FindRefreshToken(ctx, tenantID, hash)
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
			// Benign concurrency: the legitimate client raced itself and the winning request
			// already minted a fresh pair. Surface the distinct ErrRefreshConcurrent sentinel
			// (which still wraps ErrRefreshTokenReused) so cookie-clearing callers preserve the
			// winner's freshly issued refresh cookie instead of logging the user out.
			return nil, tokens.ErrRefreshConcurrent
		}
		return nil, tokens.ErrRefreshTokenReused
	}

	if s.now().After(rt.ExpiresAt) {
		return nil, tokens.ErrTokenExpired
	}

	// Resolve fresh claims (status, scopes, roles, ...) at rotation time rather than
	// trusting values frozen at login.
	// Surface which family is being rotated (plus its preserved auth_time) so the provider can
	// re-evaluate per-session assurance (AMR/scopes) for this exact session rather than guessing
	// from the user alone. Without this a provider can neither preserve a legitimately elevated
	// session's AMR across a silent refresh nor avoid blanket-elevating every session of an
	// MFA-enrolled user, so the documented "AMR re-evaluated, not frozen" semantics are impossible.
	rotationCtx := tokens.WithRotationContext(ctx, tokens.RotationContext{FamilyID: rt.FamilyID, AuthTime: rt.AuthTime})
	claims, err := s.claimsProvider.ClaimsForUser(rotationCtx, rt.UserID, rt.TenantID)
	if err != nil {
		return nil, err
	}

	// Atomically consume (single-use). Losing this race means another in-flight request
	// rotated the SAME not-yet-consumed token first. That is benign concurrency (parallel
	// tabs, link prefetch, concurrent sub-resource loads), NOT theft — so we reject this
	// request WITHOUT revoking the family. A genuine replay is still caught above on the
	// next presentation, once ConsumedAt has been set by the completed rotation.
	if err := s.store.ConsumeRefreshToken(ctx, tenantID, hash); err != nil {
		// Losing the consume race returns ErrRefreshTokenReused from the store: a parallel
		// request consumed the SAME not-yet-consumed token first. That is benign concurrency,
		// not theft — report it as ErrRefreshConcurrent so the winner's freshly minted cookies
		// are preserved rather than cleared. Any other store error propagates unchanged.
		if errors.Is(err, tokens.ErrRefreshTokenReused) {
			event.Emit(ctx, s.events, event.Event{Type: event.RefreshReuseDetected, UserID: rt.UserID.String(), TenantID: rt.TenantID, Reason: "consume_race"})
			return nil, tokens.ErrRefreshConcurrent
		}
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
	// Carry the forced-password-change gate forward verbatim, overriding whatever the
	// ClaimsProvider returned: the refreshed token must be flagged if and only if the family it
	// descends from was flagged. This makes the soft gate survive every silent refresh — a flagged
	// user cannot escape WithPasswordChangeGate by waiting for the access token to expire — without
	// re-querying the credential's state on each refresh. The flag is dropped only by minting a
	// fresh family (a new login after the password is changed); to force a change on an active
	// session, an administrator revokes the user's families (e.g. via SetTemporaryPassword's
	// erasers).
	claims.MustChangePassword = rt.MustChangePassword

	// Issue a new pair within the SAME family to preserve the rotation chain. initial=false:
	// a rotation never manufactures a fresh auth_time — claims.AuthTime (set above from the
	// family's preserved value, which may be zero for a legacy token) is taken verbatim.
	return s.issuePair(ctx, claims, rt.FamilyID, false)
}

// VerifyAccessTokenForTenant validates an access token and binds it to tenantID, mirroring
// the fail-closed tenant scoping of VerifyRefreshToken / VerifyAPIKey. It first runs the full
// signature/expiry/issuer/audience validation of VerifyAccessToken, then rejects the token with
// ErrTenantMismatch unless its signed tenant_id claim equals tenantID. Multi-tenant callers
// served by a single shared signing key MUST use this entry point (or perform the equivalent
// comparison themselves): a token minted for tenant A is otherwise cryptographically valid in
// tenant B's context, since the signing key is shared. Single-tenant callers issue under the
// empty tenant and pass "".
func (s *Service[C]) VerifyAccessTokenForTenant(ctx context.Context, tenantID string, tokenStr string) (*tokens.Claims[C], error) {
	claims, err := s.verifyAccessToken(ctx, tenantID, tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.TenantID != tenantID {
		return nil, tokens.ErrTenantMismatch
	}
	return claims, nil
}

// VerifyAPIKey validates an API key against the store and returns its claims.
// tenantID scopes the store lookup to a single tenant's partition: a key saved under a
// real tenant resolves only when the matching tenantID is passed, and verification fails
// closed (not-found) otherwise. Single-tenant callers pass "" (the default partition).
//
// It enforces expiry: a key past its ExpiresAt returns tokens.ErrTokenExpired. Use
// VerifyAPIKeyActor when the caller needs the classified egauth.Actor (key type, key ID,
// scopes, subject) in addition to the claims.
func (s *Service[C]) VerifyAPIKey(ctx context.Context, tenantID string, key string, rc ...event.RequestContext) (*tokens.Claims[C], error) {
	apiKey, err := s.verifyAPIKey(ctx, tenantID, key, rc...)
	if err != nil {
		return nil, err
	}
	return &apiKey.Claims, nil
}

// VerifyAPIKeyActor validates an API key exactly like VerifyAPIKey (same store lookup, same
// fail-closed tenant scoping and the same tokens.ErrTokenExpired on an expired key) and, in
// addition to the claims, returns the egauth.Actor that classifies the request the key
// authenticates. The Actor carries the key's Kind (PAT→egauth.PAT, Service→egauth.Service),
// its KeyID, its Scopes, and — for a PAT — the owning UserID; a Service key leaves UserID zero
// since its subject is the key's own ID (held in KeyID). It is the entry point the audit and
// middleware epics use so a verified key always yields the same Actor shape. No secret (the
// presented key or its stored hash) is exposed on either return value.
func (s *Service[C]) VerifyAPIKeyActor(ctx context.Context, tenantID string, key string, rc ...event.RequestContext) (egauth.Actor, *tokens.Claims[C], error) {
	apiKey, err := s.verifyAPIKey(ctx, tenantID, key, rc...)
	if err != nil {
		return egauth.Actor{}, nil, err
	}
	return tokens.ActorFromAPIKey(apiKey), &apiKey.Claims, nil
}

// RevokeAPIKey soft-revokes the API key identified by keyID within tenantID by delegating to the
// store, then emits an api_key.revoked audit event when the store reports success.
//
// Error/no-op semantics follow the store contract: a missing or cross-tenant key returns
// tokens.ErrAPIKeyNotFound (no event is emitted); revoking an already-revoked key is a store-level
// no-op that returns nil and still emits, since the administrative intent succeeded.
//
// The audit event mirrors api_key.created's no-secret contract — it carries the affected key_id and
// never the clear-text token or its hash. It does NOT carry key_type/created_by: the store's revoke
// is by ID and returns no row, and the APIKeyStore exposes no by-ID read, so sourcing those fields
// would require either a creator-scoped re-listing (the creator UUID is not known here) or a hash
// lookup (the hash is unrecoverable by design). key_id alone unambiguously identifies the revoked
// key for the audit trail without an extra read.
func (s *Service[C]) RevokeAPIKey(ctx context.Context, tenantID string, keyID uuid.UUID) error {
	if err := s.store.RevokeAPIKey(ctx, tenantID, keyID); err != nil {
		return err
	}

	event.Emit(ctx, s.events, event.Event{
		Type:     event.APIKeyRevoked,
		TenantID: tenantID,
		Attrs: map[string]any{
			"key_id": keyID.String(),
		},
	})

	return nil
}

// ListAPIKeysByCreator returns every API key — active and revoked — created by createdBy within
// tenantID, delegating to the store. The returned keys carry a blank Token (the clear-text value
// exists only at creation) and a populated RevokedAt on any soft-revoked key, so management tooling
// can distinguish active from revoked keys. An empty (non-nil) slice is returned when the creator
// has no keys; this is not an error.
func (s *Service[C]) ListAPIKeysByCreator(ctx context.Context, tenantID string, createdBy uuid.UUID) ([]*tokens.APIKey[C], error) {
	return s.store.ListAPIKeysByCreator(ctx, tenantID, createdBy)
}

// verifyAPIKey is the shared lookup + expiry check behind VerifyAPIKey and VerifyAPIKeyActor.
// It returns the full stored APIKey (no clear-text token — the store never persists one) so the
// callers can project it to claims and/or an Actor.
func (s *Service[C]) verifyAPIKey(ctx context.Context, tenantID string, key string, rc ...event.RequestContext) (*tokens.APIKey[C], error) {
	// reqCtx is the (optional) caller-supplied client IP / User-Agent, copied into the Attrs of
	// every api_key.auth.* event below so the audit trail carries the request's origin; when no
	// context is supplied it contributes nothing.
	reqCtx := event.RequestContextFrom(rc...)

	hash := tokens.HashToken(key)

	apiKey, err := s.store.FindAPIKeyByHash(ctx, tenantID, hash)
	if err != nil {
		// Map the store error to the correct audit reason. ErrAPIKeyNotFound covers both "no
		// such key" and the tenant-scoped lookup finding nothing for this tenant (stores return
		// ErrAPIKeyNotFound rather than ErrTenantMismatch on a cross-tenant hash hit, since the
		// hash lookup is always tenant-scoped in the WHERE clause). We emit not_found for both;
		// a tenant_mismatch distinction would require a cross-tenant secondary lookup which is
		// out of scope for this iteration.
		reason := event.ReasonAPIKeyNotFound
		if errors.Is(err, tokens.ErrTenantMismatch) {
			reason = event.ReasonAPIKeyTenantMismatch
		}
		event.Emit(ctx, s.events, event.Event{
			Type:     event.APIKeyAuthFailed,
			TenantID: tenantID,
			Reason:   reason,
			Attrs:    reqCtx.ApplyTo(nil),
		})
		return nil, err
	}

	// Reject a soft-revoked key BEFORE the expiry check so revocation produces its own distinct
	// error (ErrAPIKeyRevoked) rather than being masked by expiry, and before any claims are
	// projected. The store still returns revoked keys (RevokedAt populated) so management tooling
	// can see them; this verify layer is the single chokepoint that turns RevokedAt into a
	// rejection, so no verify path (VerifyAPIKey / VerifyAPIKeyActor and their wrappers) can
	// forget to filter.
	if apiKey.RevokedAt != nil {
		event.Emit(ctx, s.events, event.Event{
			Type:     event.APIKeyAuthFailed,
			TenantID: tenantID,
			Reason:   event.ReasonAPIKeyRevoked,
			Attrs:    reqCtx.ApplyTo(nil),
		})
		return nil, tokens.ErrAPIKeyRevoked
	}

	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(s.now()) {
		event.Emit(ctx, s.events, event.Event{
			Type:     event.APIKeyAuthFailed,
			TenantID: tenantID,
			Reason:   event.ReasonAPIKeyExpired,
			Attrs:    reqCtx.ApplyTo(nil),
		})
		return nil, tokens.ErrTokenExpired
	}

	event.Emit(ctx, s.events, event.Event{
		Type:     event.APIKeyAuthSucceeded,
		TenantID: tenantID,
		Attrs: reqCtx.ApplyTo(map[string]any{
			"key_type": string(apiKey.Type),
		}),
	})

	return apiKey, nil
}

// DeleteExpired delegates to the store's TokenReaper to purge expired refresh tokens and
// API keys within tenantID, and emits api_key.purged with the deleted count in Attrs.
// This method satisfies tokens.TokenReaper so callers can use the Service directly as the
// schedulable sweeper rather than bypassing the event layer by calling the store directly.
// A nil event sink is a safe no-op.
func (s *Service[C]) DeleteExpired(ctx context.Context, tenantID string) (int64, error) {
	n, err := s.store.DeleteExpired(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	event.Emit(ctx, s.events, event.Event{
		Type:     event.APIKeyPurged,
		TenantID: tenantID,
		Attrs: map[string]any{
			"count": n,
		},
	})
	return n, nil
}
