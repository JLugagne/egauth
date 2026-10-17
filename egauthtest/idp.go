package egauthtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/clock"
)

// IdPUser is the identity the fake provider asserts after a sign-in.
type IdPUser struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// IdP is a fake OpenID Connect provider on a loopback TLS server: discovery, authorization, token,
// userinfo and JWKS endpoints, ID tokens signed with a throwaway ES256 key. It is as strict as a
// conforming provider so that a client regression fails: authorization requires state, nonce and an
// S256 PKCE challenge; the token endpoint requires the authorization_code grant, the verifier and
// client authentication (client_secret_post or client_secret_basic) by the client the code was
// issued to. The browser sign-in is simulated: Authorize immediately redirects back as the current
// user.
type IdP struct {
	server *httptest.Server
	key    *ecdsa.PrivateKey
	kid    string
	clock  clock.Clock

	mu    sync.Mutex
	user  IdPUser
	codes map[string]grant
	token map[string]IdPUser
}

type grant struct {
	user      IdPUser
	clientID  string
	redirect  string
	nonce     string
	challenge string
}

const (
	idpClientID     = "egauthtest-client"
	idpClientSecret = "egauthtest-secret"
)

// NewIdP starts the fake provider and stops it when t ends. Times in ID tokens come from clk, or
// from the wall clock when clk is nil, which is what an Auth without a test clock checks them
// against. The initial user is subject "idp-user-1" with a verified email.
func NewIdP(t testing.TB, clk *Clock) *IdP {
	t.Helper()
	var c clock.Clock
	if clk != nil {
		c = clk.Library()
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &IdP{
		key:   key,
		kid:   "egauthtest-1",
		clock: c,
		user:  IdPUser{Subject: "idp-user-1", Email: "user@idp.example", EmailVerified: true, Name: "Test User"},
		codes: map[string]grant{},
		token: map[string]IdPUser{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.exchange)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	mux.HandleFunc("GET /jwks", p.jwks)
	p.server = httptest.NewTLSServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

// Issuer returns the issuer URL, which is also the origin of every endpoint.
func (p *IdP) Issuer() string { return p.server.URL }

// ClientID returns the client id Provider registers.
func (p *IdP) ClientID() string { return idpClientID }

// ClientSecret returns the client secret the token endpoint requires with ClientID, by
// client_secret_post or client_secret_basic. It is public and protects nothing.
func (p *IdP) ClientSecret() string { return idpClientSecret }

// SetUser replaces the identity asserted by the next sign-ins.
func (p *IdP) SetUser(u IdPUser) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.user = u
}

// Provider returns the egauth federation spec of the fake provider under name, trusting its
// verified emails. It carries Issuer and JWKSURL, so it needs no discovery.
func (p *IdP) Provider(name string) federation.Provider {
	return federation.Provider{
		Name:              name,
		ClientID:          idpClientID,
		ClientSecret:      federation.NewSecret(idpClientSecret),
		AuthURL:           p.server.URL + "/authorize",
		TokenURL:          p.server.URL + "/token",
		UserInfoURL:       p.server.URL + "/userinfo",
		Scopes:            []string{"openid", "email", "profile"},
		Issuer:            p.server.URL,
		JWKSURL:           p.server.URL + "/jwks",
		EmailVerification: federation.Always,
	}
}

// HTTPClient returns a client that trusts the provider's certificate, follows no redirect and gives up
// after 60 seconds.
func (p *IdP) HTTPClient() *http.Client {
	c := p.server.Client()
	c.Timeout = 60 * time.Second
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// IDToken is what SignIDToken signs; an empty Nonce is omitted.
type IDToken struct {
	User     IdPUser
	Audience string
	Nonce    string
}

// SignIDToken returns t signed by the provider, valid for ten minutes from the provider clock. It
// fails only when the system random source does.
func (p *IdP) SignIDToken(t IDToken) (string, error) {
	u, audience, nonce := t.User, t.Audience, t.Nonce
	now := p.clock.Now()
	claims := map[string]any{
		"iss": p.server.URL, "sub": u.Subject, "aud": audience,
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"email": u.Email, "email_verified": u.EmailVerified, "name": u.Name,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	header := map[string]any{"alg": "ES256", "typ": "JWT", "kid": p.kid}
	input := segment(header) + "." + segment(claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, digest[:])
	if err != nil {
		return "", errors.Join(errors.New("egauthtest: signing the id_token"), err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func segment(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (p *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize",
		"token_endpoint": p.server.URL + "/token", "userinfo_endpoint": p.server.URL + "/userinfo",
		"jwks_uri": p.server.URL + "/jwks", "response_types_supported": []string{"code"},
		"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"ES256"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (p *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	point, err := p.key.PublicKey.Bytes()
	if err != nil || len(point) != 65 {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	x, y := point[1:33], point[33:]
	writeJSON(w, map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": p.kid,
		"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y),
	}}})
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if q.Get("response_type") != "code" || q.Get("client_id") != idpClientID || err != nil || redirect.Scheme == "" ||
		q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" ||
		!challengeShaped(q.Get("code_challenge")) {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	code := random()
	p.mu.Lock()
	p.codes[code] = grant{user: p.user, clientID: q.Get("client_id"), redirect: q.Get("redirect_uri"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	p.mu.Unlock()
	back := redirect.Query()
	back.Set("code", code)
	back.Set("state", q.Get("state"))
	back.Set("iss", p.server.URL)
	redirect.RawQuery = back.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *IdP) exchange(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	if form.Get("grant_type") != "authorization_code" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	client, ok := authenticate(r, form)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]string{"error": "invalid_client"})
		return
	}
	p.mu.Lock()
	g, ok := p.codes[form.Get("code")]
	delete(p.codes, form.Get("code"))
	p.mu.Unlock()
	if !ok || client != g.clientID || form.Get("redirect_uri") != g.redirect || !pkceHolds(g.challenge, form.Get("code_verifier")) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant"})
		return
	}
	access := random()
	p.mu.Lock()
	p.token[access] = g.user
	p.mu.Unlock()
	idToken, err := p.SignIDToken(IDToken{User: g.user, Audience: g.clientID, Nonce: g.nonce})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": 600, "id_token": idToken,
	})
}

func (p *IdP) userinfo(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	p.mu.Lock()
	u, ok := p.token[h[len(prefix):]]
	p.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"sub": u.Subject, "email": u.Email, "email_verified": u.EmailVerified, "name": u.Name})
}

func authenticate(r *http.Request, form url.Values) (string, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		if form.Has("client_secret") {
			return "", false
		}
		if form.Has("client_id") && form.Get("client_id") != id {
			return "", false
		}
	} else {
		id, secret = form.Get("client_id"), form.Get("client_secret")
	}
	idOK := subtle.ConstantTimeCompare([]byte(id), []byte(idpClientID)) == 1
	secretOK := subtle.ConstantTimeCompare([]byte(secret), []byte(idpClientSecret)) == 1
	return id, idOK && secretOK
}

func challengeShaped(challenge string) bool {
	b, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(b) == sha256.Size
}

func pkceHolds(challenge, verifier string) bool {
	if challenge == "" || len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

func random() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
