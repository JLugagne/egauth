package e2esecurity_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/janitor"
	"github.com/JLugagne/egauth/oauth"
	"github.com/JLugagne/egauth/otp"
	otpmemory "github.com/JLugagne/egauth/otp/memory"
	"github.com/JLugagne/egauth/tokens"
	tokenjwt "github.com/JLugagne/egauth/tokens/jwt"
	tokenmemory "github.com/JLugagne/egauth/tokens/memory"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SEC-GLO-06 (CVSS 5.8): Cross-tenant collision and overwrite prevention in memory token store.
// The in-memory token store (tokens/memory/store.go) indexes refresh tokens and API keys by
// a composite key (tenantID, hash). When Tenant B saves a token/key with the same hash as Tenant A,
// both records are preserved without collision.
func TestSecGlo06_TokenMemoryStore_CrossTenantHashCollisionOverwrite(t *testing.T) {
	ctx := context.Background()
	store := tokenmemory.NewStore[struct{}]()

	const sharedHash = "sha256-shared-collision-hash-001"
	userA := uuid.New()
	userB := uuid.New()

	// 1. Tenant A saves a refresh token with sharedHash
	rtA := &tokens.RefreshToken{
		Hash:      sharedHash,
		UserID:    userA,
		FamilyID:  uuid.New(),
		TenantID:  "tenant-A",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, store.SaveRefreshToken(ctx, "tenant-A", rtA))

	// Tenant A can retrieve its token successfully
	foundA, err := store.FindRefreshToken(ctx, "tenant-A", sharedHash)
	require.NoError(t, err)
	assert.Equal(t, "tenant-A", foundA.TenantID)
	assert.Equal(t, userA, foundA.UserID)

	// 2. Tenant B saves a refresh token with the exact same hash
	rtB := &tokens.RefreshToken{
		Hash:      sharedHash,
		UserID:    userB,
		FamilyID:  uuid.New(),
		TenantID:  "tenant-B",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, store.SaveRefreshToken(ctx, "tenant-B", rtB))

	// 3. Assert remediation: Tenant A's refresh token is preserved despite Tenant B saving the same hash
	foundAAfterB, err := store.FindRefreshToken(ctx, "tenant-A", sharedHash)
	require.NoError(t, err)
	assert.Equal(t, "tenant-A", foundAAfterB.TenantID)
	assert.Equal(t, userA, foundAAfterB.UserID)

	// Tenant B can retrieve it
	foundB, err := store.FindRefreshToken(ctx, "tenant-B", sharedHash)
	require.NoError(t, err)
	assert.Equal(t, "tenant-B", foundB.TenantID)
	assert.Equal(t, userB, foundB.UserID)

	// 4. Verification for API keys
	const sharedKeyHash = "sha256-shared-api-key-hash-002"
	keyA := &tokens.APIKey[struct{}]{
		ID:        uuid.New(),
		Hash:      sharedKeyHash,
		TenantID:  "tenant-A",
		CreatedBy: userA,
		Type:      tokens.KeyTypePAT,
	}
	require.NoError(t, store.SaveAPIKey(ctx, "tenant-A", keyA))

	keyB := &tokens.APIKey[struct{}]{
		ID:        uuid.New(),
		Hash:      sharedKeyHash,
		TenantID:  "tenant-B",
		CreatedBy: userB,
		Type:      tokens.KeyTypePAT,
	}
	require.NoError(t, store.SaveAPIKey(ctx, "tenant-B", keyB))

	// Tenant A can still find its API key with no error
	foundKeyA, err := store.FindAPIKeyByHash(ctx, "tenant-A", sharedKeyHash)
	require.NoError(t, err)
	assert.Equal(t, "tenant-A", foundKeyA.TenantID)
	assert.Equal(t, userA, foundKeyA.CreatedBy)

	foundKeyB, err := store.FindAPIKeyByHash(ctx, "tenant-B", sharedKeyHash)
	require.NoError(t, err)
	assert.Equal(t, "tenant-B", foundKeyB.TenantID)
	assert.Equal(t, userB, foundKeyB.CreatedBy)
}

// SEC-GLO-08: Anonymous actor classification and role/group vanishing remediation verification.
// Part 1: An empty/zero-value Actor (Kind == "", UserID == uuid.Nil) returns IsHuman() == false and IsAnonymous() == true.
// Part 2: tokens/middleware.go:actorFromClaims propagates claims.Roles and claims.Groups into egauth.Actor.
func TestSecGlo08_Actor_AnonymousClassifiedAsHuman_AndRolesVanishing(t *testing.T) {
	// Part 1: Verification of IsHuman() and IsAnonymous() on empty/anonymous Actor
	var unauthenticatedActor egauth.Actor
	assert.Equal(t, egauth.PrincipalKind(""), unauthenticatedActor.Kind)
	assert.Equal(t, uuid.Nil, unauthenticatedActor.UserID)

	assert.False(t, unauthenticatedActor.IsHuman(),
		"Zero-value unauthenticated Actor must not be classified as Human")
	assert.True(t, unauthenticatedActor.IsAnonymous(),
		"Zero-value unauthenticated Actor must be classified as Anonymous")
	assert.False(t, unauthenticatedActor.IsMachine())

	// Part 2: Propagation of Roles and Groups into Actor
	ctx := context.Background()
	userUUID := uuid.New()
	secret := "01234567890123456789012345678901" // 32 bytes
	tokenStore := tokenmemory.NewStore[struct{}]()

	jwtSvc := tokenjwt.New(tokenjwt.Config[struct{}]{
		SecretKey: secret,
		Store:     tokenStore,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{}, nil
		}),
		Issuer:     "egauth-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})

	claimsWithRoles := tokens.Claims[struct{}]{
		Subject:  userUUID,
		TenantID: "tenant-corp",
		Kind:     egauth.User,
		Roles:    []string{"admin", "billing_manager"},
		Groups:   []string{"engineers", "security"},
		Scopes:   []string{"read:reports"},
	}

	pair, err := jwtSvc.IssueTokenPair(ctx, claimsWithRoles)
	require.NoError(t, err)

	// Verify that when RequireAuth invokes next handler, Roles and Groups are preserved in egauth.Actor
	var capturedActor egauth.Actor

	handler := tokens.RequireAuth[struct{}](jwtSvc, func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, custom struct{}) {
		capturedActor = actor
		w.WriteHeader(http.StatusOK)
	}, tokens.WithAuthTenantResolver[struct{}](func(r *http.Request) string {
		return "tenant-corp"
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, userUUID, capturedActor.UserID)
	assert.Equal(t, "tenant-corp", capturedActor.TenantID)
	assert.Equal(t, []string{"read:reports"}, capturedActor.Scopes)
	assert.Equal(t, []string{"admin", "billing_manager"}, capturedActor.Roles)
	assert.Equal(t, []string{"engineers", "security"}, capturedActor.Groups)
	assert.True(t, capturedActor.HasRole("admin"))
	assert.True(t, capturedActor.HasGroup("engineers"))
	assert.True(t, capturedActor.HasScope("read:reports"))
}

// SEC-OAU-09 (CVSS 4.8): Défaut de filtrage des algorithmes symétriques (none, HMAC) dans AllowedAlgs.
// The OIDCConfig documentation explicitly specifies:
// "none and HMAC algorithms are always rejected regardless of this list."
// However, newOIDCVerifier performs no validation or stripping on cfg.AllowedAlgs, accepting
// "none" and "HS256" into the verifier's allowed list without error.
func TestSecOau09_AllowedAlgs_AcceptsSymmetricAndNoneAlgorithms(t *testing.T) {
	// Provider with AllowedAlgs set to "none" and "HS256"
	p := oauth.New("custom-oidc", "client-id", "client-secret",
		"https://auth.example.com/authorize",
		"https://auth.example.com/token",
		[]string{"openid", "email"},
		nil,
		oauth.WithOIDC(oauth.OIDCConfig{
			Issuer:      "https://idp.example.com",
			AllowedAlgs: []string{"none", "HS256", "HS512"},
		}),
	)

	// Exchange fails if configErr is set; verify configErr is NOT set for none/HMAC
	_, err := p.Exchange(context.Background(), "code", "https://app.com/cb", "")

	// Flaw confirmed: Exchange does NOT return an invalid algorithm error!
	// It proceeds to attempt network fetch to token endpoint, showing AllowedAlgs was accepted.
	assert.NotContains(t, fmt.Sprint(err), "algorithm",
		"Flaw confirmed: WithOIDC accepted 'none' and HMAC algorithms without raising an algorithm error")
}

// SEC-GLO-07 (CVSS 6.3): Désynchronisation de tenant entre tokens.ContextMiddleware et otp.SubjectResolver.
// tokens.SubjectResolverFromContext extracts only (UserID, true) from the context Actor and ignores
// Actor.TenantID. When otp.IssueHandler runs behind tokens.ContextMiddleware without an explicit
// WithTenantResolver, cfg.tenant(r) defaults to "" (the default/empty tenant). The OTP is issued
// and stored under tenant "", causing verification under the actual user's tenant to fail.
func TestSecGlo07_OTP_TenantDesynchronization_TokensContextMiddleware(t *testing.T) {
	ctx := context.Background()
	otpStore := otpmemory.NewStore()
	otpSvc := otp.NewService(otpStore, otp.WithTTL(5*time.Minute), otp.WithMaxAttempts(3))

	userUUID := uuid.New()
	const userTenant = "tenant-enterprise-42"
	const purpose = "sudo_action"

	secret := "01234567890123456789012345678901"
	tokenStore := tokenmemory.NewStore[struct{}]()
	jwtSvc := tokenjwt.New(tokenjwt.Config[struct{}]{
		SecretKey: secret,
		Store:     tokenStore,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{}, nil
		}),
		Issuer:     "egauth-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})

	// Mint access token bound to userTenant
	pair, err := jwtSvc.IssueTokenPair(ctx, tokens.Claims[struct{}]{
		Subject:  userUUID,
		TenantID: userTenant,
		Kind:     egauth.User,
	})
	require.NoError(t, err)

	delivered := make(chan string, 1)
	deliverFunc := func(ctx context.Context, ch *otp.Challenge) error {
		delivered <- ch.Code
		return nil
	}

	// Mount IssueHandler using tokens.SubjectResolverFromContext without an explicit tenant resolver
	rawIssueHandler := otp.IssueHandler(otpSvc, deliverFunc,
		otp.WithSubjectResolver(tokens.SubjectResolverFromContext),
		otp.WithPurpose(purpose),
		otp.WithInsecureNoOriginCheck(),
	)
	// Wrap with ContextMiddleware (with tenant resolver to accept tenant token)
	contextMiddleware := tokens.ContextMiddleware[struct{}](jwtSvc, rawIssueHandler,
		tokens.WithAuthTenantResolver[struct{}](func(r *http.Request) string {
			return userTenant
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "/otp/issue", strings.NewReader("action=confirm"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()

	contextMiddleware.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)

	var issuedCode string
	select {
	case issuedCode = <-delivered:
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for OTP delivery")
	}
	require.NotEmpty(t, issuedCode)

	// Flaw confirmed: Verifying under the user's actual tenant fails with ErrCodeNotFound!
	err = otpSvc.Verify(ctx, userTenant, userUUID, purpose, issuedCode)
	assert.ErrorIs(t, err, otp.ErrCodeNotFound,
		"Flaw confirmed: Challenge was NOT saved under user's actual tenant")

	// Instead, the challenge was saved under the empty tenant partition ""!
	errEmptyTenant := otpSvc.Verify(ctx, "", userUUID, purpose, issuedCode)
	assert.NoError(t, errEmptyTenant,
		"Flaw confirmed: Challenge was saved under empty tenant partition '' due to resolver desync")
}

// SEC-GLO-10 (CVSS 5.3): Indefinite blocking on Janitor shutdown (janitor.Stop).
// janitor.Start launches a background loop that invokes fn() without passing context.Context.
// When j.Stop() is called, it waits unconditionally on <-j.done. If fn() is performing a
// long-running or hanging operation, Stop() blocks indefinitely until fn() completes.
func TestSecGlo10_JanitorStop_BlocksIndefinitelyOnLongRunningCleanup(t *testing.T) {
	ctx := context.Background()
	fnStarted := make(chan struct{})
	blocker := make(chan struct{})

	// Start a janitor with an operation that blocks on blocker channel
	j := janitor.Start(ctx, 1*time.Millisecond, func() {
		close(fnStarted)
		<-blocker // Simulates long-running DB transaction or lock contention
	})

	// Wait until fn() starts executing
	select {
	case <-fnStarted:
	case <-time.After(1 * time.Second):
		t.Fatal("Janitor fn() did not start in time")
	}

	// Call Stop() in a separate goroutine
	stopFinished := make(chan struct{})
	go func() {
		j.Stop()
		close(stopFinished)
	}()

	// Confirm that Stop() does NOT return while fn() is running
	select {
	case <-stopFinished:
		t.Fatal("Stop() returned while fn() was still blocked!")
	case <-time.After(50 * time.Millisecond):
		// Flaw confirmed: Stop() is blocked waiting for fn() to finish
	}

	// Once the blocker is released, Stop() finally finishes
	close(blocker)
	select {
	case <-stopFinished:
		// Succeeded after unblocking
	case <-time.After(1 * time.Second):
		t.Fatal("Stop() did not finish even after unblocking fn()")
	}
}

// SEC-OAU-06 (CVSS 6.9): Sanitize Host and X-Forwarded-Proto in redirect_uri derivation.
// When WithRedirectURL is not provided, resolveRedirectURL validates r.Host against WithAllowedHosts.
// Requests with an untrusted host are rejected with HTTP 400 Bad Request, while legitimate
// hosts produce the expected redirect URI.
func TestSecOau06_ResolveRedirectURL_UnsanitizedHostAndForwardedProto(t *testing.T) {
	p := oauth.New("mock-provider", "client-id", "client-secret",
		"https://provider.example.com/oauth/authorize",
		"https://provider.example.com/oauth/token",
		[]string{"read"},
		nil,
	)

	// BeginHandler configured with WithAllowedHosts
	beginHandler := oauth.BeginHandler(p, oauth.WithAllowedHosts("app.example.com"))

	// 1. Host header poisoning attempt is rejected with 400 Bad Request
	reqAttack := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
	reqAttack.Host = "evil.attacker.com"
	reqAttack.Header.Set("X-Forwarded-Proto", "https")
	recAttack := httptest.NewRecorder()

	beginHandler.ServeHTTP(recAttack, reqAttack)
	assert.Equal(t, http.StatusBadRequest, recAttack.Code,
		"Untrusted host header must be rejected with 400 Bad Request")

	// 2. Legitimate host produces the expected redirect URI
	reqLegit := httptest.NewRequest(http.MethodGet, "/oauth/begin", nil)
	reqLegit.Host = "app.example.com"
	reqLegit.Header.Set("X-Forwarded-Proto", "https")
	recLegit := httptest.NewRecorder()

	beginHandler.ServeHTTP(recLegit, reqLegit)
	require.Equal(t, http.StatusFound, recLegit.Code)

	location := recLegit.Header().Get("Location")
	require.NotEmpty(t, location)

	parsedURL, err := url.Parse(location)
	require.NoError(t, err)

	redirectURI := parsedURL.Query().Get("redirect_uri")
	assert.Equal(t, "https://app.example.com/oauth/begin", redirectURI,
		"Legitimate host must produce the expected redirect URI")
}

// SEC-OAU-07 (CVSS 5.3): Suivi automatique non sécurisé des redirections HTTP (307/308) avec fuite de client_secret.
// In oauth.Provider.Exchange, http.Client has no CheckRedirect policy (it is nil by default).
// If the token endpoint returns a 307 Temporary Redirect, Go's http.Client automatically repeats
// the POST request including client_secret to the redirected destination.
func TestSecOau07_TokenExchange_Follows307RedirectWithClientSecret(t *testing.T) {
	var capturedClientSecret string
	var redirectFollowed atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			// Token endpoint redirects with 307 Temporary Redirect
			http.Redirect(w, r, "/stolen-token-sink", http.StatusTemporaryRedirect)
		case "/stolen-token-sink":
			redirectFollowed.Store(true)
			_ = r.ParseForm()
			capturedClientSecret = r.Form.Get("client_secret")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"dummy","token_type":"Bearer"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Use default http.Client (CheckRedirect == nil) as configured in oauth.New
	p := oauth.New("redirect-test", "victim-client-id", "super-secret-client-token-999",
		srv.URL+"/auth",
		srv.URL+"/token",
		[]string{"read"},
		func(ctx context.Context, c *http.Client, token string) (*oauth.UserInfo, error) {
			return &oauth.UserInfo{ProviderID: "123", Email: "test@example.com"}, nil
		},
		oauth.WithInsecureURLs(),
	)

	_, _ = p.Exchange(context.Background(), "auth-code", srv.URL+"/callback", "")

	// Flaw confirmed: Default http.Client automatically followed the 307 redirect and transmitted the client_secret!
	assert.True(t, redirectFollowed.Load(), "Flaw confirmed: HTTP 307 redirect was automatically followed")
	assert.Equal(t, "super-secret-client-token-999", capturedClientSecret,
		"Flaw confirmed: client_secret was leaked to the redirected URL")
}

// SEC-OAU-05 (CVSS 7.5): DoS and Amplification mitigation via JWKS negative caching and rate limiting.
// Unknown kids are negatively cached and refresh requests are rate limited to prevent outbound amplification DoS.
func TestSecOau05_JWKSCache_NoNegativeCaching_FetchesEveryUnknownKid(t *testing.T) {
	var jwksRequests atomic.Int32

	// Setup mock OIDC server
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, "http://"+r.Host, "http://"+r.Host+"/jwks")
		case "/jwks":
			jwksRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			n := base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes())
			_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":"valid-key-id","use":"sig","alg":"RS256","n":%q,"e":%q}]}`, n, e)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Mint an id_token with an unknown kid: "bogus-kid-1"
	tokenBogus1 := mintTestIDToken(t, rsaKey, "bogus-kid-1", srv.URL, "client-id", "nonce-1")

	reqBody := fmt.Sprintf(`{"id_token":%q}`, tokenBogus1)
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reqBody)
	}))
	defer tokenSrv.Close()

	pTest := oauth.New("test-jwks", "client-id", "secret",
		srv.URL+"/auth",
		tokenSrv.URL,
		[]string{"openid"},
		nil,
		oauth.WithInsecureURLs(),
		oauth.WithOIDC(oauth.OIDCConfig{
			Issuer:            srv.URL,
			AllowInsecureURLs: true,
			HTTPClient:        srv.Client(),
		}),
	)

	// 1st request with unknown kid
	_, err = pTest.Exchange(context.Background(), "code1", "http://callback", "", oauth.WithExpectedNonce("nonce-1"))
	assert.Error(t, err)
	assert.Equal(t, int32(1), jwksRequests.Load(), "First lookup of bogus-kid-1 made 1 JWKS request")

	// 2nd request with the EXACT SAME unknown kid!
	// With negative caching, it must NOT trigger another JWKS network fetch.
	_, err = pTest.Exchange(context.Background(), "code2", "http://callback", "", oauth.WithExpectedNonce("nonce-1"))
	assert.Error(t, err)
	assert.Equal(t, int32(1), jwksRequests.Load(),
		"Second lookup of identical bogus-kid-1 must use negative cache and not trigger another JWKS request")
}

// SEC-OAU-08 (CVSS 5.3): Absence de validation du paramètre iss (RFC 9207) dans CallbackHandler.
// RFC 9207 requires that if the authorization response contains an "iss" parameter, the client MUST
// validate that its value equals the authorization server's issuer identifier.
// CallbackHandler ignores the iss parameter completely, proceeding with state and code processing.
func TestSecOau08_CallbackHandler_IgnoresRFC9207IssuerParameter(t *testing.T) {
	p := oauth.New("google", "client-id", "secret",
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token",
		[]string{"openid", "email"},
		nil,
	)

	// Create CallbackHandler with dummy linker and issuer
	dummyLinker := &mockIdentityLinker{}
	dummyIssuer := &mockTokenIssuer{}
	callbackHandler := oauth.CallbackHandler[struct{}](p, dummyLinker, dummyIssuer, nil,
		oauth.WithInsecureCookies(),
	)

	// Send callback request with state and code, PLUS a malicious/mismatching "iss" parameter
	// RFC 9207 Section 2.2: MUST abort with error if iss != expected issuer.
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state=invalid_or_valid&code=xyz&iss=https://evil-attacker-idp.com", nil)
	rec := httptest.NewRecorder()

	callbackHandler.ServeHTTP(rec, req)

	// The handler rejects due to missing/invalid state cookie (403 invalid_state),
	// NOT due to issuer mismatch! It never examined "iss".
	assert.NotEqual(t, "issuer_mismatch", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "invalid_state",
		"Flaw confirmed: CallbackHandler inspects state and provider, but never validates the RFC 9207 'iss' parameter")
}

// Helpers

func mintTestIDToken(t *testing.T, key *rsa.PrivateKey, kid, iss, aud, nonce string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":            iss,
		"aud":            aud,
		"sub":            "test-sub",
		"email":          "test@example.com",
		"email_verified": true,
		"nonce":          nonce,
		"exp":            float64(time.Now().Add(time.Hour).Unix()),
		"iat":            float64(time.Now().Unix()),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	str, err := tok.SignedString(key)
	require.NoError(t, err)
	return str
}

type mockIdentityLinker struct{}

func (m *mockIdentityLinker) LinkOrCreateIdentity(ctx context.Context, tenantID, provider, providerID, email string, emailVerified bool) (*identity.User, error) {
	return &identity.User{ID: uuid.New()}, nil
}

type mockTokenIssuer struct{}

func (m *mockTokenIssuer) IssueTokenPair(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
	return &tokens.TokenPair[struct{}]{AccessToken: "acc", RefreshToken: "ref"}, nil
}

func (m *mockTokenIssuer) IssueAPIKey(ctx context.Context, prefix string, keyType tokens.KeyType, createdBy uuid.UUID, claims tokens.Claims[struct{}]) (*tokens.APIKey[struct{}], error) {
	return &tokens.APIKey[struct{}]{ID: uuid.New()}, nil
}
