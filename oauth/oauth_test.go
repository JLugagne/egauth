package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- stubs ---------------------------------------------------------------------------------

type stubLinker struct {
	user          *identity.User
	err           error
	gotProvider   string
	gotProviderID string
	gotEmail      string
	gotVerified   bool
}

func (s *stubLinker) LinkOrCreateIdentity(_ context.Context, _ string, provider, providerID, email string, emailVerified bool) (*identity.User, error) {
	s.gotProvider, s.gotProviderID, s.gotEmail, s.gotVerified = provider, providerID, email, emailVerified
	if s.err != nil {
		return nil, s.err
	}
	return s.user, nil
}

type stubIssuer struct {
	pair *tokens.TokenPair[struct{}]
	err  error
}

func (s *stubIssuer) IssueTokenPair(_ context.Context, _ tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
	return s.pair, s.err
}

func (s *stubIssuer) IssueAPIKey(_ context.Context, _ string, _ tokens.KeyType, _ uuid.UUID, _ tokens.Claims[struct{}]) (*tokens.APIKey[struct{}], error) {
	return nil, nil
}

func claimsOf(u *identity.User) tokens.Claims[struct{}] {
	return tokens.Claims[struct{}]{Subject: u.ID}
}

// stubProviderServer returns an httptest server emulating a provider's token + userinfo
// endpoints, plus a Provider wired to it. The userinfo body is taken from *body at call time.
func stubProviderServer(t *testing.T, body *string) (*Provider, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"at-123","token_type":"bearer"}`)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer at-123", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, *body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	fetch := func(ctx context.Context, c *http.Client, accessToken string) (*UserInfo, error) {
		var u struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := GetJSON(ctx, c, srv.URL+"/userinfo", accessToken, &u); err != nil {
			return nil, err
		}
		return &UserInfo{ProviderID: u.Sub, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.Name}, nil
	}
	p := New("test", "cid", "csecret", srv.URL+"/auth", srv.URL+"/token",
		[]string{"email"}, fetch, WithHTTPClient(srv.Client()), WithInsecureURLs())
	return p, srv
}

// --- unit tests ----------------------------------------------------------------------------

func TestNewPKCE_ChallengeIsS256(t *testing.T) {
	verifier, challenge, err := newPKCE()
	require.NoError(t, err)
	require.NotEmpty(t, verifier)

	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	assert.Equal(t, want, challenge, "challenge must be BASE64URL(SHA256(verifier))")
}

func TestAuthCodeURL(t *testing.T) {
	p := New("google", "client-id", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token", []string{"openid", "email", "profile"}, nil)
	raw := p.AuthCodeURL("the-state", "https://app.example.com/cb", "the-challenge")

	u, err := url.Parse(raw)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "client-id", q.Get("client_id"))
	assert.Equal(t, "https://app.example.com/cb", q.Get("redirect_uri"))
	assert.Equal(t, "the-state", q.Get("state"))
	assert.Equal(t, "the-challenge", q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Contains(t, q.Get("scope"), "email")
}

func TestExchange(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)

	info, err := p.Exchange(context.Background(), "auth-code", "https://app/cb", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "prov-1", info.ProviderID)
	assert.Equal(t, "u@example.com", info.Email)
	assert.True(t, info.EmailVerified)
}

// --- handler tests -------------------------------------------------------------------------

const testRedirect = "https://app.example.com/auth/test/callback"

func runBegin(t *testing.T, p *Provider, opts ...HandlerOption) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	BeginHandler(p, opts...)(rec, httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))
	require.Equal(t, http.StatusFound, rec.Code)

	res := rec.Result()
	var state *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == DefaultStateCookieName {
			state = c
		}
	}
	require.NotNil(t, state, "begin must set the state cookie")
	assert.True(t, state.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, state.SameSite)

	loc, err := url.Parse(res.Header.Get("Location"))
	require.NoError(t, err)
	return state, loc.Query().Get("state")
}

func runCallback(t *testing.T, p *Provider, linker IdentityLinker, issuer tokens.Issuer[struct{}], stateCookie *http.Cookie, query string, opts ...HandlerOption) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/test/callback?"+query, nil)
	if stateCookie != nil {
		req.AddCookie(stateCookie)
	}
	CallbackHandler[struct{}](p, linker, issuer, claimsOf, opts...)(rec, req)
	return rec
}

func TestCallbackHandler_Success(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)

	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	require.Equal(t, http.StatusNoContent, rec.Code)
	// Provider identity was forwarded for linking.
	assert.Equal(t, "test", linker.gotProvider)
	assert.Equal(t, "prov-1", linker.gotProviderID)
	assert.Equal(t, "u@example.com", linker.gotEmail)
	assert.True(t, linker.gotVerified)

	// Auth cookies issued; state cookie cleared.
	cookies := rec.Result().Cookies()
	var gotAccess, gotRefresh, stateCleared bool
	for _, c := range cookies {
		switch c.Name {
		case tokens.DefaultAccessCookieName:
			gotAccess = c.Value == "access"
		case tokens.DefaultRefreshCookieName:
			gotRefresh = c.Value == "refresh"
		case DefaultStateCookieName:
			stateCleared = c.MaxAge < 0
		}
	}
	assert.True(t, gotAccess, "access cookie must be set")
	assert.True(t, gotRefresh, "refresh cookie must be set")
	assert.True(t, stateCleared, "state cookie must be cleared")
}

func TestCallbackHandler_StateMismatchRejected(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com"}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, _ := runBegin(t, p, WithRedirectURL(testRedirect))

	rec := runCallback(t, p, &stubLinker{}, &stubIssuer{}, stateCookie,
		url.Values{"state": {"forged-state"}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCallbackHandler_MissingStateCookieRejected(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com"}`
	p, _ := stubProviderServer(t, &body)

	rec := runCallback(t, p, &stubLinker{}, &stubIssuer{}, nil,
		url.Values{"state": {"whatever"}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCallbackHandler_ProviderErrorRejected(t *testing.T) {
	body := `{}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	rec := runCallback(t, p, &stubLinker{}, &stubIssuer{}, stateCookie,
		url.Values{"state": {state}, "error": {"access_denied"}}.Encode(),
		WithRedirectURL(testRedirect))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCallbackHandler_EmailMissingRejected(t *testing.T) {
	body := `{"sub":"prov-1","email":"","email_verified":false}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	rec := runCallback(t, p, &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7())}}, &stubIssuer{}, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCallbackHandler_UnverifiedEmailRejectedByDefault(t *testing.T) {
	body := `{"sub":"prov-1","email":"squat@example.com","email_verified":false}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7())}}
	rec := runCallback(t, p, linker, &stubIssuer{}, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	assert.Equal(t, http.StatusBadRequest, rec.Code, "unverified provider email must be rejected by default")
	assert.Empty(t, linker.gotProviderID, "linker must not be reached for an unverified email")
}

func TestCallbackHandler_UnverifiedEmailAllowedWithOptIn(t *testing.T) {
	body := `{"sub":"prov-1","email":"squat@example.com","email_verified":false}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "squat@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}}
	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithAllowUnverifiedEmail())

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "prov-1", linker.gotProviderID, "opt-in must let the unverified email through")
}

func TestCallbackHandler_AccountExistsConflict(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{err: identity.ErrEmailAlreadyExists}
	rec := runCallback(t, p, linker, &stubIssuer{}, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestCallbackHandler_RFC9207IssuerMismatchRejected(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)
	WithExpectedIssuer("https://accounts.google.com")(p)

	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{
			"state": {state},
			"code":  {"auth-code"},
			"iss":   {"https://evil-idp.com"},
		}.Encode(),
		WithRedirectURL(testRedirect),
	)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "issuer_mismatch")
	assert.Empty(t, linker.gotProviderID, "identity linker must not be reached on issuer mismatch")
}

func TestCallbackHandler_RFC9207IssuerMatchSucceeds(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)
	WithExpectedIssuer("https://accounts.google.com")(p)

	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{
			"state": {state},
			"code":  {"auth-code"},
			"iss":   {"https://accounts.google.com/"},
		}.Encode(),
		WithRedirectURL(testRedirect),
	)

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "prov-1", linker.gotProviderID)
}

func TestProvider_RFC9207IssuerResolutionAndValidation(t *testing.T) {
	t.Run("explicit WithExpectedIssuer takes highest priority", func(t *testing.T) {
		p := New("test", "cid", "sec", "https://auth.example.com/oauth/authorize", "https://auth.example.com/oauth/token",
			nil, nil, WithExpectedIssuer("https://custom-issuer.example.com"))
		assert.Equal(t, "https://custom-issuer.example.com", p.ExpectedIssuer())
		assert.True(t, p.ValidateIssuer("https://custom-issuer.example.com"))
		assert.True(t, p.ValidateIssuer("https://custom-issuer.example.com/"))
		assert.False(t, p.ValidateIssuer("https://other-issuer.example.com"))
	})

	t.Run("derived from authURL origin when no explicit or oidc issuer", func(t *testing.T) {
		p := New("test", "cid", "sec", "https://accounts.google.com/o/oauth2/v2/auth?prompt=consent", "https://oauth2.googleapis.com/token",
			nil, nil)
		assert.Equal(t, "https://accounts.google.com", p.ExpectedIssuer())
		assert.True(t, p.ValidateIssuer("https://accounts.google.com"))
		assert.True(t, p.ValidateIssuer("https://accounts.google.com/"))
		assert.False(t, p.ValidateIssuer("https://evil-idp.com"))
	})

	t.Run("empty issuer allows any issuer when origin cannot be determined", func(t *testing.T) {
		p := &Provider{}
		assert.Equal(t, "", p.ExpectedIssuer())
		assert.True(t, p.ValidateIssuer("https://any-issuer.com"))
	})
}

// TestGetJSON_BoundsOversizedResponse proves the outbound read cap (io.LimitReader with
// maxResponseBytes in GetJSON) is load-bearing: a hostile/oversized upstream userinfo body is
// truncated at the cap, so a document larger than maxResponseBytes is cut off mid-JSON and the
// decode fails with ErrUserInfoFailed rather than the client reading an unbounded body into
// memory. This is the DoS guard against a malicious provider (or MITM) returning a giant body.
func TestGetJSON_BoundsOversizedResponse(t *testing.T) {
	ctx := context.Background()

	// A valid JSON object whose padding pushes the total length well past the read cap. The
	// LimitReader stops at maxResponseBytes, dropping the trailing bytes (including the closing
	// quote and brace), so json.Unmarshal sees malformed, truncated input.
	pad := strings.Repeat("a", maxResponseBytes+(1<<10))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sub":"`+pad+`"}`)
	}))
	t.Cleanup(srv.Close)

	var dst struct {
		Sub string `json:"sub"`
	}
	err := GetJSON(ctx, srv.Client(), srv.URL, "at-token", &dst)
	require.ErrorIs(t, err, ErrUserInfoFailed,
		"an over-cap upstream body must be truncated and fail to decode, not be read unbounded")

	// Positive control: a body comfortably under the cap decodes normally, proving the cap only
	// bites oversized responses.
	small := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sub":"ok"}`)
	}))
	t.Cleanup(small.Close)
	require.NoError(t, GetJSON(ctx, small.Client(), small.URL, "at-token", &dst))
	assert.Equal(t, "ok", dst.Sub)
}

// Ensure identity.Service satisfies the IdentityLinker interface the callback depends on.
var _ IdentityLinker = identity.Service(nil)

// TestExchange_RefusesRedirects verifies that the OAuth client does not follow redirects (e.g. 307/308)
// during token exchange, preventing client_secret leakage to unauthorized destinations (SEC-OAU-07).
func TestExchange_RefusesRedirects(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var redirectFollowed atomic.Bool
			var capturedSecret string

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/token":
					http.Redirect(w, r, "/redirected-sink", status)
				case "/redirected-sink":
					redirectFollowed.Store(true)
					_ = r.ParseForm()
					capturedSecret = r.Form.Get("client_secret")
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"access_token":"leaked","token_type":"Bearer"}`))
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(srv.Close)

			p := New("test", "client-id", "secret-key",
				srv.URL+"/auth", srv.URL+"/token", []string{"email"},
				func(ctx context.Context, c *http.Client, token string) (*UserInfo, error) {
					return &UserInfo{ProviderID: "1"}, nil
				},
				WithInsecureURLs(),
			)

			info, err := p.Exchange(context.Background(), "code", srv.URL+"/callback", "")
			require.Error(t, err, "Exchange must return an error when token endpoint returns redirect")
			assert.Nil(t, info)
			assert.False(t, redirectFollowed.Load(), "redirect must not be followed")
			assert.Empty(t, capturedSecret, "client_secret must not be sent to redirect target")
			assert.Contains(t, err.Error(), "redirects are disabled for security")
		})
	}

	t.Run("WithHTTPClient also disables redirects", func(t *testing.T) {
		var redirectFollowed atomic.Bool
		var capturedSecret string

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/token":
				http.Redirect(w, r, "/redirected-sink", http.StatusTemporaryRedirect)
			case "/redirected-sink":
				redirectFollowed.Store(true)
				_ = r.ParseForm()
				capturedSecret = r.Form.Get("client_secret")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"leaked","token_type":"Bearer"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)

		customClient := srv.Client() // default srv.Client() follows redirects
		p := New("test", "client-id", "secret-key",
			srv.URL+"/auth", srv.URL+"/token", []string{"email"},
			func(ctx context.Context, c *http.Client, token string) (*UserInfo, error) {
				return &UserInfo{ProviderID: "1"}, nil
			},
			WithHTTPClient(customClient),
			WithInsecureURLs(),
		)

		info, err := p.Exchange(context.Background(), "code", srv.URL+"/callback", "")
		require.Error(t, err, "Exchange must return an error when token endpoint returns redirect")
		assert.Nil(t, info)
		assert.False(t, redirectFollowed.Load(), "redirect must not be followed with custom client")
		assert.Empty(t, capturedSecret, "client_secret must not be sent to redirect target")
		assert.Contains(t, err.Error(), "redirects are disabled for security")
	})
}
