package oauth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testStateKey = []byte("libauth-oauth-test-state-signing-key")

func TestUnpackState_MissingKeyRejectsUnsigned(t *testing.T) {
	forged := "attacker-state" + "." + "" + "." + "" + "." +
		base64.RawURLEncoding.EncodeToString([]byte("test")) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(""))
	_, _, _, _, _, ok := unpackState(forged, nil)
	assert.False(t, ok, "unsigned state cookie must be rejected when no signing key is set")

	packed := packState("s", "v", "n", "test", "", nil)
	_, _, _, _, _, ok = unpackState(packed, nil)
	assert.False(t, ok, "packState without a key must not produce an acceptable state value")
}

func TestDefaultStateCookieName_IsHostPrefixed(t *testing.T) {
	require.True(t, strings.HasPrefix(DefaultStateCookieName, "__Host-"),
		"the default state cookie name must carry the __Host- prefix (STATE-01)")
}

func TestBeginHandler_HostLockedStateCookieAttributes(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)

	rec := httptest.NewRecorder()
	BeginHandler(p, WithRedirectURL(testRedirect), WithStateSigningKey(testStateKey))(
		rec, httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))
	require.Equal(t, http.StatusFound, rec.Code)

	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == DefaultStateCookieName {
			sc = c
		}
	}
	require.NotNil(t, sc, "begin must set the state cookie")
	assert.True(t, sc.HttpOnly)
	assert.True(t, sc.Secure, "__Host- state cookie must be Secure")
	assert.Empty(t, sc.Domain, "__Host- state cookie must be host-only")
	assert.Equal(t, "/", sc.Path, "__Host- state cookie must have Path=/")
	assert.Equal(t, http.SameSiteLaxMode, sc.SameSite)
}

func TestCallbackHandler_ForgedUnsignedStateCookieRejectedWithoutKey(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)

	forged := "attacker-state" + "." + "" + "." + "" + "." +
		base64.RawURLEncoding.EncodeToString([]byte("test")) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(""))
	forgedCookie := &http.Cookie{Name: DefaultStateCookieName, Value: forged}

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/auth/test/callback?"+url.Values{"state": {"attacker-state"}, "code": {"auth-code"}}.Encode(), nil)
	req.AddCookie(forgedCookie)
	CallbackHandler[struct{}](p, linker, issuer, claimsOf, WithRedirectURL(testRedirect))(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"a handler without a state signing key must fail closed, not drive issuance from a forged cookie")
	assert.Empty(t, linker.gotProvider, "no identity linking may occur from a forged state cookie")
	var issuedAuth bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == tokens.DefaultAccessCookieName && c.Value == "access" {
			issuedAuth = true
		}
	}
	assert.False(t, issuedAuth, "no auth cookies may be issued from a forged state cookie")
}

func TestDynamicBeginHandler_MissingSigningKeyFailsClosed(t *testing.T) {
	body := `{"sub":"prov-1"}`
	p, _ := stubProviderServer(t, &body)
	store := NewMemoryStore()
	store.AddProvider("", p)

	rec := httptest.NewRecorder()
	DynamicBeginHandler(store, p.Name())(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"begin must fail closed without a state signing key")
}

func TestValidateHandlerConfig_RequiresSigningKey(t *testing.T) {
	err := ValidateHandlerConfig()
	require.Error(t, err, "a handler config without a state signing key must fail the startup check (STATE-01)")
	assert.Contains(t, err.Error(), "WithStateSigningKey")
}

func TestValidateHandlerConfig_HostPrefixAttributes(t *testing.T) {
	base := []HandlerOption{WithStateSigningKey(testStateKey)}

	require.NoError(t, ValidateHandlerConfig(base...), "a signing key is the only requirement for a plain config")
	require.NoError(t, ValidateHandlerConfig(append(append([]HandlerOption(nil), base...),
		WithStateCookieName("oauth_state"), WithCookieDomain("example.com"))...),
		"non-__Host- name + Domain is the documented cross-subdomain opt-out")
	require.NoError(t, ValidateHandlerConfig(append(append([]HandlerOption(nil), base...),
		WithStateCookieName("oauth_state"), WithInsecureCookies())...),
		"non-__Host- name + insecure cookies is allowed for plaintext HTTP dev")

	err := ValidateHandlerConfig(append(append([]HandlerOption(nil), base...), WithCookieDomain("example.com"))...)
	require.Error(t, err, "the default __Host- name rejects a shared Domain")
	assert.Contains(t, err.Error(), "Domain")

	err = ValidateHandlerConfig(append(append([]HandlerOption(nil), base...), WithInsecureCookies())...)
	require.Error(t, err, "the default __Host- name rejects insecure cookies")
	assert.Contains(t, err.Error(), "Secure")
}
