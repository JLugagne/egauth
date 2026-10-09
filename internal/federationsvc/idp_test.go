package federationsvc_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/clock"
)

type idpUser struct {
	Subject       string
	Email         string
	EmailVerified bool
}

type authorizeRequest struct {
	RedirectURI string
	State       string
	Nonce       string
	Challenge   string
	Scope       string
}

type tokenTamper struct {
	Audience      string
	Issuer        string
	Nonce         string
	ExpiresIn     time.Duration
	OmitIDToken   bool
	ForeignKey    bool
	Alg           string
	IssParam      string
	OmitIssParam  bool
	TokenStatus   int
	UserInfoSubID string
}

type fakeIdP struct {
	t        *testing.T
	server   *httptest.Server
	issuer   string
	clock    *clock.Test
	ec       *ecdsa.PrivateKey
	rsa      *rsa.PrivateKey
	ed       ed25519.PrivateKey
	foreign  *ecdsa.PrivateKey
	oidc     bool
	mu       sync.Mutex
	user     idpUser
	tamper   tokenTamper
	codes    map[string]grant
	tokens   map[string]idpUser
	lastAuth authorizeRequest
	redeemed []url.Values
}

type grant struct {
	user      idpUser
	redirect  string
	nonce     string
	challenge string
}

const (
	idpClientID     = "client-1"
	idpClientSecret = "client-secret-1"
)

func newIdP(t *testing.T, clk *clock.Test, oidc bool, issuerPath string) *fakeIdP {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{
		t: t, clock: clk, ec: ec, rsa: rk, ed: ed, foreign: foreign, oidc: oidc,
		user:   idpUser{Subject: "idp-sub-1", Email: "alice@example.org", EmailVerified: true},
		codes:  map[string]grant{},
		tokens: map[string]idpUser{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	mux.HandleFunc("GET /jwks", p.jwks)
	p.server = httptest.NewTLSServer(mux)
	t.Cleanup(p.server.Close)
	p.issuer = p.server.URL + issuerPath
	mux.HandleFunc("GET "+issuerPath+"/.well-known/openid-configuration", p.discovery)
	return p
}

func (p *fakeIdP) client() *http.Client {
	c := p.server.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func (p *fakeIdP) provider(name string, ev federation.EmailVerification) federation.Provider {
	spec := federation.Provider{
		Name:              name,
		ClientID:          idpClientID,
		ClientSecret:      federation.NewSecret(idpClientSecret),
		AuthURL:           p.server.URL + "/authorize",
		TokenURL:          p.server.URL + "/token",
		UserInfoURL:       p.server.URL + "/userinfo",
		Scopes:            []string{"email", "profile"},
		EmailVerification: ev,
	}
	if p.oidc {
		spec.Issuer = p.issuer
		spec.JWKSURL = p.server.URL + "/jwks"
	}
	return spec
}

func (p *fakeIdP) setUser(u idpUser) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.user = u
}

func (p *fakeIdP) setTamper(tt tokenTamper) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tamper = tt
}

func (p *fakeIdP) last() authorizeRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastAuth
}

func (p *fakeIdP) redemptions() []url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]url.Values(nil), p.redeemed...)
}

func (p *fakeIdP) discovery(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	issuer := p.issuer
	if p.tamper.Issuer != "" {
		issuer = p.tamper.Issuer
	}
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": issuer, "authorization_endpoint": p.server.URL + "/authorize",
		"token_endpoint": p.server.URL + "/token", "userinfo_endpoint": p.server.URL + "/userinfo",
		"jwks_uri": p.server.URL + "/jwks",
	})
}

func (p *fakeIdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || q.Get("response_type") != "code" || q.Get("client_id") != idpClientID || q.Get("state") == "" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || (p.oidc && q.Get("nonce") == "") {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	code := randomString()
	p.mu.Lock()
	p.lastAuth = authorizeRequest{
		RedirectURI: q.Get("redirect_uri"), State: q.Get("state"), Nonce: q.Get("nonce"),
		Challenge: q.Get("code_challenge"), Scope: q.Get("scope"),
	}
	p.codes[code] = grant{user: p.user, redirect: q.Get("redirect_uri"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	tamper := p.tamper
	p.mu.Unlock()
	back := redirect.Query()
	back.Set("code", code)
	back.Set("state", q.Get("state"))
	if p.oidc && !tamper.OmitIssParam {
		iss := p.issuer
		if tamper.IssParam != "" {
			iss = tamper.IssParam
		}
		back.Set("iss", iss)
	}
	redirect.RawQuery = back.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	p.mu.Lock()
	p.redeemed = append(p.redeemed, f)
	g, ok := p.codes[f.Get("code")]
	delete(p.codes, f.Get("code"))
	tamper := p.tamper
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if !ok || f.Get("grant_type") != "authorization_code" || f.Get("client_id") != idpClientID ||
		f.Get("client_secret") != idpClientSecret || f.Get("redirect_uri") != g.redirect ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if tamper.TokenStatus != 0 {
		writeJSON(w, tamper.TokenStatus, map[string]string{"error": "server_error"})
		return
	}
	access := randomString()
	p.mu.Lock()
	p.tokens[access] = g.user
	p.mu.Unlock()
	body := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 600}
	if p.oidc && !tamper.OmitIDToken {
		body["id_token"] = p.idToken(g, tamper)
	}
	writeJSON(w, http.StatusOK, body)
}

func (p *fakeIdP) idToken(g grant, tamper tokenTamper) string {
	now := p.clock.Now()
	aud, iss, nonce, ttl := idpClientID, p.issuer, g.nonce, 10*time.Minute
	if tamper.Audience != "" {
		aud = tamper.Audience
	}
	if tamper.Issuer != "" {
		iss = tamper.Issuer
	}
	if tamper.Nonce != "" {
		nonce = tamper.Nonce
	}
	if tamper.ExpiresIn != 0 {
		ttl = tamper.ExpiresIn
	}
	c := map[string]any{
		"iss": iss, "sub": g.user.Subject, "aud": aud, "iat": now.Unix(), "exp": now.Add(ttl).Unix(),
		"nonce": nonce, "email": g.user.Email, "email_verified": g.user.EmailVerified,
	}
	alg := tamper.Alg
	if alg == "" {
		alg = "ES256"
	}
	kid := map[string]string{"ES256": "ec-1", "RS256": "rsa-1", "EdDSA": "ed-1", "HS256": "ec-1", "none": "ec-1"}[alg]
	input := segment(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"}) + "." + segment(c)
	return input + "." + base64.RawURLEncoding.EncodeToString(p.sign(alg, input, tamper.ForeignKey))
}

func (p *fakeIdP) sign(alg, input string, foreign bool) []byte {
	digest := sha256.Sum256([]byte(input))
	switch alg {
	case "RS256":
		sig, err := rsa.SignPKCS1v15(rand.Reader, p.rsa, crypto.SHA256, digest[:])
		if err != nil {
			p.t.Fatal(err)
		}
		return sig
	case "EdDSA":
		return ed25519.Sign(p.ed, []byte(input))
	case "none":
		return nil
	}
	key := p.ec
	if foreign {
		key = p.foreign
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		p.t.Fatal(err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

func (p *fakeIdP) userinfo(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	p.mu.Lock()
	u, ok := p.tokens[h[min(len(prefix), len(h)):]]
	sub := p.tamper.UserInfoSubID
	p.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if sub == "" {
		sub = u.Subject
	}
	if p.oidc {
		writeJSON(w, http.StatusOK, map[string]any{"sub": sub, "email": u.Email, "email_verified": u.EmailVerified})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": json.Number("4242"), "email": u.Email, "email_verified": u.EmailVerified})
}

func (p *fakeIdP) jwks(w http.ResponseWriter, _ *http.Request) {
	ec := p.ec.PublicKey
	ecb, err := ec.Bytes()
	if err != nil {
		p.t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{
		{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "ec-1", "x": b64(ecb[1:33]), "y": b64(ecb[33:])},
		{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "rsa-1", "n": b64(p.rsa.N.Bytes()), "e": b64(big.NewInt(int64(p.rsa.E)).Bytes())},
		{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": "ed-1", "x": b64(p.ed.Public().(ed25519.PublicKey))},
	}})
}

func segment(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomString() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
