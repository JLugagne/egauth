package egauthtest_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/principal"
)

func TestConfigBuildsAnAuthOnceStorageIsAssigned(t *testing.T) {
	cfg := egauthtest.Config[struct{}]()
	cfg.Storage = memstore.New(cfg.KEK)
	a, err := egauth.New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	require.NoError(t, a.Ready(context.Background()))
}

func TestConfigWithoutStorageIsRefused(t *testing.T) {
	_, err := egauth.New(egauthtest.Config[struct{}]())
	require.Error(t, err)
	require.Contains(t, err.Error(), "Storage")
}

func TestConfigOptOutsAreExactlyTheAcknowledgedTestOnes(t *testing.T) {
	cfg := egauthtest.Config[struct{}]()
	cfg.Storage = memstore.New(cfg.KEK)
	a, err := egauth.New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	require.Equal(t, []egauth.OptOut{{Name: "NoRateLimit", Reason: egauthtest.TestOptOutReason}}, a.Posture().OptOuts)
}

func TestConfigMailboxIsTheEmailDeliverer(t *testing.T) {
	cfg := egauthtest.Config[struct{}]()
	box, ok := cfg.Email.(*egauthtest.Mailbox)
	require.True(t, ok)
	require.NoError(t, box.PasswordResetLink(context.Background(), egauth.LinkMessage{To: "a@example.com", Link: "https://x/reset?t=1"}))
	require.NoError(t, box.LoginCode(context.Background(), egauth.CodeMessage{To: "a@example.com", Code: "123456"}))
	m, ok := box.Last("PasswordResetLink")
	require.True(t, ok)
	require.Equal(t, "https://x/reset?t=1", m.Link)
	_, ok = box.Last("MagicLink")
	require.False(t, ok)
	require.Len(t, box.Messages(), 2)
}

func TestClockOnlyMovesWhenDriven(t *testing.T) {
	c := egauthtest.NewClock(time.Time{})
	require.Equal(t, egauthtest.ReferenceTime(), c.Now())
	c.Advance(time.Hour)
	require.Equal(t, egauthtest.ReferenceTime().Add(time.Hour), c.Now())
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	c.Set(at)
	require.Equal(t, at, c.Now())
}

func TestResolvedReadsBackDefaults(t *testing.T) {
	cfg := egauthtest.Config[struct{}]()
	cfg.Storage = memstore.New(cfg.KEK)
	r := egauthtest.Resolved(cfg)
	require.Empty(t, r.Problems())
	v, ok := r.Get("Policy.IdleTimeout")
	require.True(t, ok)
	require.Equal(t, 168*time.Hour, v)
	require.True(t, r.Defaulted("Policy.IdleTimeout"))
	require.Contains(t, r.Applied(), "BasePath")
	require.False(t, r.Defaulted("PublicOrigin"))
	_, ok = r.Get("No.Such.Field")
	require.False(t, ok)
}

func TestResolvedReportsProblems(t *testing.T) {
	r := egauthtest.Resolved(egauth.Config[struct{}]{})
	require.NotEmpty(t, r.Problems())
	require.Contains(t, strings.Join(r.Problems(), "\n"), "PublicOrigin")
}

func TestNewPrincipalSessionDefaults(t *testing.T) {
	p := mustPrincipal[struct{}](t, egauthtest.PrincipalSpec{})
	require.Equal(t, egauth.Session, p.Kind())
	s, ok := p.Session()
	require.True(t, ok)
	require.True(t, s.HasFactor(principal.FactorPassword))
	require.Equal(t, principal.TransportCookies, s.Transport())
	require.False(t, p.Subject().IsZero())
	require.True(t, p.Subject().Tenant.IsZero())
	id, ok := p.SessionID()
	require.True(t, ok)
	require.NotEqual(t, uuid.Nil, id)
	require.Equal(t, egauth.Session, p.Kind())
	c := p.Caller()
	require.Equal(t, principal.CallerSession, c.Kind())
	_, isKey := p.APIKey()
	require.False(t, isKey)
}

func TestNewPrincipalHonoursEverySessionField(t *testing.T) {
	tn, err := principal.ParseTenantID("acme")
	require.NoError(t, err)
	sub := principal.Subject{Tenant: tn, User: uuid.New()}
	line := uuid.New()
	at := egauthtest.ReferenceTime().Add(-time.Hour)
	type claims struct{ Plan string }
	p := mustPrincipal[claims](t, egauthtest.PrincipalSpec{
		Subject: sub, Lineage: line,
		UsedFactors: []principal.Factor{principal.FactorPasskey, principal.FactorTOTP},
		PasskeyID:   []byte{1, 2, 3}, SecurityEpoch: 9, MustChange: true, Remembered: true, ReturnPath: "/x",
		Transport: principal.TransportBearer, Provider: "corp",
		PrimaryAt: at, SecondAt: at.Add(time.Minute), CreatedAt: at.Add(-time.Hour), ClaimsFetchedAt: at.Add(time.Second),
		Roles: []string{"admin"}, Groups: []string{"g"}, Scopes: []string{"s"}, Custom: claims{Plan: "pro"},
	})
	s, _ := p.Session()
	require.Equal(t, sub, p.Subject())
	require.Equal(t, line, s.Lineage())
	require.True(t, s.MultiFactor())
	require.Equal(t, uint64(9), s.Epoch())
	require.True(t, s.MustChangePassword())
	require.True(t, s.RememberMe())
	require.Equal(t, "/x", s.ReturnTo())
	require.Equal(t, principal.TransportBearer, s.Transport())
	require.Equal(t, "corp", s.Provider())
	require.Equal(t, at, s.PrimaryAt())
	require.Equal(t, at.Add(time.Minute), s.SecondAt())
	require.Equal(t, at.Add(time.Second), s.ClaimsFetchedAt())
	require.Equal(t, claims{Plan: "pro"}, p.Claims().Custom)
	require.Equal(t, []string{"admin"}, p.Claims().Roles)
	sc, ok := p.Caller().Session()
	require.True(t, ok)
	require.Equal(t, line, sc.Lineage())
}

func TestNewPrincipalAPIKey(t *testing.T) {
	p := mustPrincipal[struct{}](t, egauthtest.PrincipalSpec{
		Machine: &egauth.APIKeyInfo{Kind: "service", Name: "ci"},
		Scopes:  []string{"read"},
	})
	require.Equal(t, egauth.APIKey, p.Kind())
	k, ok := p.APIKey()
	require.True(t, ok)
	require.Equal(t, "service", k.Kind)
	require.Equal(t, p.Subject(), k.Owner)
	require.NotEqual(t, uuid.Nil, k.ID)
	_, isSession := p.Session()
	require.False(t, isSession)
	require.Equal(t, principal.CallerAPIKey, p.Caller().Kind())
}

func TestNewPrincipalRefusesAWrongCustomType(t *testing.T) {
	_, err := egauthtest.NewPrincipal[struct{ A int }](egauthtest.PrincipalSpec{Custom: "not a struct"})
	require.Error(t, err)
}

func TestIdPProviderSpecIsComplete(t *testing.T) {
	idp := egauthtest.NewIdP(t, nil)
	prov := idp.Provider("corp")
	require.NoError(t, prov.Complete())
	require.False(t, prov.NeedsDiscovery())
	require.True(t, prov.Verified("a@b.example", true))
	require.False(t, prov.Verified("a@b.example", false))
}

func TestIdPDiscoveryMatchesTheSpec(t *testing.T) {
	idp := egauthtest.NewIdP(t, nil)
	var doc map[string]any
	getJSON(t, idp, idp.Issuer()+"/.well-known/openid-configuration", &doc)
	prov := idp.Provider("corp")
	require.Equal(t, prov.Issuer, doc["issuer"])
	require.Equal(t, prov.AuthURL, doc["authorization_endpoint"])
	require.Equal(t, prov.TokenURL, doc["token_endpoint"])
	require.Equal(t, prov.JWKSURL, doc["jwks_uri"])
}

func TestIdPCodeFlowIssuesAVerifiableIDToken(t *testing.T) {
	clk := egauthtest.NewClock(time.Time{})
	idp := egauthtest.NewIdP(t, clk)
	idp.SetUser(egauthtest.IdPUser{Subject: "u-7", Email: "u7@idp.example", EmailVerified: true, Name: "U Seven"})
	verifier := "verifier-verifier-verifier-verifier-verifier-1"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	code, state := authorize(t, idp, challenge)
	require.Equal(t, "st-1", state)
	tok := exchange(t, idp, code, verifier, http.StatusOK)
	idToken, _ := tok["id_token"].(string)
	claims := verifyIDToken(t, idp, idToken)
	require.Equal(t, idp.Issuer(), claims["iss"])
	require.Equal(t, idp.ClientID(), claims["aud"])
	require.Equal(t, "u-7", claims["sub"])
	require.Equal(t, "n-1", claims["nonce"])
	require.Equal(t, true, claims["email_verified"])
	require.EqualValues(t, clk.Now().Add(10*time.Minute).Unix(), claims["exp"])

	req, err := http.NewRequest(http.MethodGet, idp.Issuer()+"/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	resp, err := idp.HTTPClient().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var info map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&info))
	require.Equal(t, "u7@idp.example", info["email"])
}

func TestIdPRefusesAWrongVerifierAndAReusedCode(t *testing.T) {
	idp := egauthtest.NewIdP(t, nil)
	verifier := "verifier-verifier-verifier-verifier-verifier-1"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	code, _ := authorize(t, idp, challenge)
	exchange(t, idp, code, "wrong-verifier", http.StatusBadRequest)
	exchange(t, idp, code, verifier, http.StatusBadRequest)

	code, _ = authorize(t, idp, challenge)
	exchange(t, idp, code, verifier, http.StatusOK)
	exchange(t, idp, code, verifier, http.StatusBadRequest)
}

func TestIdPAuthorizeRefusesAnUnknownClient(t *testing.T) {
	idp := egauthtest.NewIdP(t, nil)
	q := url.Values{"response_type": {"code"}, "client_id": {"other"}, "redirect_uri": {"https://app.example/cb"}}
	resp, err := idp.HTTPClient().Get(idp.Issuer() + "/authorize?" + q.Encode())
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func getJSON(t *testing.T, idp *egauthtest.IdP, u string, v any) {
	t.Helper()
	resp, err := idp.HTTPClient().Get(u)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(v))
}

func authorize(t *testing.T, idp *egauthtest.IdP, challenge string) (code, state string) {
	t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {idp.ClientID()}, "redirect_uri": {"https://app.example/cb"},
		"state": {"st-1"}, "nonce": {"n-1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	resp, err := idp.HTTPClient().Get(idp.Issuer() + "/authorize?" + q.Encode())
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, idp.Issuer(), loc.Query().Get("iss"))
	return loc.Query().Get("code"), loc.Query().Get("state")
}

func exchange(t *testing.T, idp *egauthtest.IdP, code, verifier string, want int) map[string]any {
	t.Helper()
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://app.example/cb"},
		"code_verifier": {verifier}, "client_id": {idp.ClientID()}, "client_secret": {idp.ClientSecret()},
	}
	resp, err := idp.HTTPClient().PostForm(idp.Issuer()+"/token", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, want, resp.StatusCode, string(body))
	var out map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	return out
}

func verifyIDToken(t *testing.T, idp *egauthtest.IdP, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	var jwks struct {
		Keys []struct {
			Kty, Crv, Alg, Kid, X string
		} `json:"keys"`
	}
	getJSON(t, idp, idp.Provider("corp").JWKSURL, &jwks)
	require.Len(t, jwks.Keys, 1)
	pub, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].X)
	require.NoError(t, err)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.True(t, ed25519.Verify(ed25519.PublicKey(pub), []byte(parts[0]+"."+parts[1]), sig))
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func mustPrincipal[C any](t *testing.T, spec egauthtest.PrincipalSpec) egauth.Principal[C] {
	t.Helper()
	p, err := egauthtest.NewPrincipal[C](spec)
	require.NoError(t, err)
	return p
}

func TestMailRedactsItsSecrets(t *testing.T) {
	m := egauthtest.Mail{Kind: "LoginCode", To: "a@example.com", Code: "123456", Link: "https://x/l?t=SECRET", RevertLink: "https://x/r?t=SECRET"}
	for _, out := range []string{m.String(), m.GoString(), fmt.Sprintf("%v %+v %#v", m, m, m)} {
		require.NotContains(t, out, "123456")
		require.NotContains(t, out, "SECRET")
	}
	require.NotContains(t, m.LogValue().String(), "123456")
}
