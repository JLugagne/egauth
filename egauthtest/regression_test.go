package egauthtest_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/egauthtest"
)

func TestDefaultIdPStampsTokensFromTheWallClock(t *testing.T) {
	idp := egauthtest.NewIdP(t, nil)
	tok, err := idp.SignIDToken(egauthtest.IDToken{User: egauthtest.IdPUser{Subject: "s"}, Audience: idp.ClientID()})
	require.NoError(t, err)
	claims := verifyIDToken(t, idp, tok)
	iat := time.Unix(int64(claims["iat"].(float64)), 0)
	require.WithinDuration(t, time.Now(), iat, time.Minute)
}

func TestClockLibraryReadsTheTestClock(t *testing.T) {
	clk := egauthtest.NewClock(time.Time{})
	lib := clk.Library()
	require.Equal(t, egauthtest.ReferenceTime(), lib.Now())
	clk.Advance(time.Hour)
	require.Equal(t, egauthtest.ReferenceTime().Add(time.Hour), lib.Now())
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeStatus(t *testing.T, idp *egauthtest.IdP, q url.Values) int {
	t.Helper()
	resp, err := idp.HTTPClient().Get(idp.Issuer() + "/authorize?" + q.Encode())
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestIdPAuthorizeRequiresS256PKCEAndANonce(t *testing.T) {
	idp := egauthtest.NewIdP(t, nil)
	base := func() url.Values {
		return url.Values{
			"response_type": {"code"}, "client_id": {idp.ClientID()}, "redirect_uri": {"https://app.example/cb"},
			"state": {"st-1"}, "nonce": {"n-1"}, "code_challenge": {s256("v")}, "code_challenge_method": {"S256"},
		}
	}
	require.Equal(t, http.StatusFound, authorizeStatus(t, idp, base()))
	for _, drop := range []string{"code_challenge", "code_challenge_method", "nonce", "state"} {
		q := base()
		q.Del(drop)
		require.Equal(t, http.StatusBadRequest, authorizeStatus(t, idp, q), "without %s", drop)
	}
	q := base()
	q.Set("code_challenge_method", "plain")
	require.Equal(t, http.StatusBadRequest, authorizeStatus(t, idp, q))
}

func postToken(t *testing.T, idp *egauthtest.IdP, form url.Values, basicUser, basicPass string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, idp.Issuer()+"/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	resp, err := idp.HTTPClient().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestIdPTokenEndpointAuthenticatesTheClient(t *testing.T) {
	idp := egauthtest.NewIdP(t, nil)
	verifier := "verifier-verifier-verifier-verifier-verifier-2"
	form := func(code string) url.Values {
		return url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://app.example/cb"},
			"code_verifier": {verifier},
		}
	}
	cases := []struct {
		name         string
		id, secret   string
		basic        bool
		wantAccepted bool
	}{
		{name: "no client authentication"},
		{name: "another client", id: "attacker", secret: idp.ClientSecret()},
		{name: "wrong secret", id: idp.ClientID(), secret: "wrong"},
		{name: "no secret", id: idp.ClientID()},
		{name: "client_secret_post", id: idp.ClientID(), secret: idp.ClientSecret(), wantAccepted: true},
		{name: "client_secret_basic", id: idp.ClientID(), secret: idp.ClientSecret(), basic: true, wantAccepted: true},
	}
	for _, c := range cases {
		code, _ := authorize(t, idp, s256(verifier))
		f := form(code)
		user, pass := "", ""
		if c.basic {
			user, pass = c.id, c.secret
		} else {
			if c.id != "" {
				f.Set("client_id", c.id)
			}
			if c.secret != "" {
				f.Set("client_secret", c.secret)
			}
		}
		status := postToken(t, idp, f, user, pass)
		if c.wantAccepted {
			require.Equal(t, http.StatusOK, status, c.name)
		} else {
			require.NotEqual(t, http.StatusOK, status, c.name)
		}
	}
}

func TestIdPTokenEndpointRefusesAMissingVerifierAndAWrongGrantType(t *testing.T) {
	idp := egauthtest.NewIdP(t, nil)
	verifier := "verifier-verifier-verifier-verifier-verifier-3"
	code, _ := authorize(t, idp, s256(verifier))
	f := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://app.example/cb"},
		"client_id": {idp.ClientID()}, "client_secret": {idp.ClientSecret()},
	}
	require.Equal(t, http.StatusBadRequest, postToken(t, idp, f, "", ""))

	code, _ = authorize(t, idp, s256(verifier))
	f.Set("code", code)
	f.Set("code_verifier", verifier)
	f.Set("grant_type", "refresh_token")
	require.Equal(t, http.StatusBadRequest, postToken(t, idp, f, "", ""))
}

func TestMailJSONRedactsItsSecrets(t *testing.T) {
	m := egauthtest.Mail{Kind: "LoginCode", To: "a@example.com", Code: "123456", Link: "https://x/l?t=SECRET", RevertLink: "https://x/r?t=SECRET", DeliveryID: "d-1"}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	require.NotContains(t, string(b), "123456")
	require.NotContains(t, string(b), "SECRET")
	require.Contains(t, string(b), "a@example.com")
}
