package federationsvc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
)

const (
	maxResponseBytes = 1 << 20
	githubAPIHost    = "api.github.com"
	githubEmailsURL  = "https://api.github.com/user/emails"
)

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func oidc(p federation.Provider) bool { return p.Issuer != "" }

func authorizationURL(p federation.Provider, state string, o ceremonycodec.OAuth) (string, error) {
	u, err := url.Parse(p.AuthURL)
	if err != nil {
		return "", err
	}
	scopes := slices.Clone(p.Scopes)
	if oidc(p) && !slices.Contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	challenge := sha256.Sum256([]byte(o.PKCEVerifier))
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", o.RedirectURI)
	q.Set("state", state)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")
	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	}
	if o.Nonce != "" {
		q.Set("nonce", o.Nonce)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

func redeem(ctx context.Context, d doer, p federation.Provider, code string, o ceremonycodec.OAuth) (tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", o.RedirectURI)
	form.Set("code_verifier", o.PKCEVerifier)
	form.Set("client_id", p.ClientID)
	if !p.ClientSecret.IsZero() {
		form.Set("client_secret", p.ClientSecret.Reveal())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := d.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	var tr tokenResponse
	if err := decodeJSON(resp, &tr); err != nil {
		return tokenResponse{}, err
	}
	if tr.AccessToken == "" && tr.IDToken == "" {
		return tokenResponse{}, errors.New("federationsvc: token response without a token")
	}
	return tr, nil
}

func decodeJSON(resp *http.Response, out any) error {
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return errors.New("federationsvc: provider answered status " + strconv.Itoa(resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxResponseBytes {
		return errors.New("federationsvc: provider response too large")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	return dec.Decode(out)
}

type claims map[string]any

func (c claims) str(key string) string {
	switch v := c[key].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	}
	return ""
}

func (c claims) flag(key string) bool {
	switch v := c[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

type profile struct {
	subject       string
	email         string
	emailVerified bool
}

func (s *Service) identify(ctx context.Context, r resolved, tr tokenResponse, nonce string) (profile, error) {
	p := r.spec
	if oidc(p) {
		return s.identifyOIDC(ctx, r, tr, nonce)
	}
	if tr.AccessToken == "" || p.UserInfoURL == "" {
		return profile{}, ErrInvalidIdentity
	}
	info := claims{}
	if err := getJSON(ctx, r.client, p.UserInfoURL, tr.AccessToken, &info); err != nil {
		return profile{}, errors.Join(ErrProviderUnavailable, err)
	}
	out := profile{subject: info.str("sub"), email: info.str("email"), emailVerified: info.flag("email_verified")}
	if out.subject == "" {
		out.subject = info.str("id")
	}
	if !out.emailVerified {
		out.emailVerified = info.flag("verified")
	}
	if u, err := url.Parse(p.UserInfoURL); err == nil && u.Host == githubAPIHost {
		email, verified, err := githubPrimaryEmail(ctx, r.client, tr.AccessToken)
		if err != nil {
			return profile{}, errors.Join(ErrProviderUnavailable, err)
		}
		out.email, out.emailVerified = email, verified
	}
	if out.subject == "" {
		return profile{}, ErrInvalidIdentity
	}
	return out, nil
}

func githubPrimaryEmail(ctx context.Context, d doer, token string) (string, bool, error) {
	var list []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := getJSON(ctx, d, githubEmailsURL, token, &list); err != nil {
		return "", false, err
	}
	for _, e := range list {
		if e.Primary {
			return e.Email, e.Verified, nil
		}
	}
	return "", false, nil
}

func (s *Service) identifyOIDC(ctx context.Context, r resolved, tr tokenResponse, nonce string) (profile, error) {
	p := r.spec
	if tr.IDToken == "" {
		return profile{}, ErrInvalidIdentity
	}
	c, err := s.verifyIDToken(ctx, r, tr.IDToken, nonce)
	if err != nil {
		return profile{}, err
	}
	out := profile{subject: c.str("sub"), email: c.str("email"), emailVerified: c.flag("email_verified")}
	if out.email != "" || p.UserInfoURL == "" || tr.AccessToken == "" {
		return out, nil
	}
	info := claims{}
	if err := getJSON(ctx, r.client, p.UserInfoURL, tr.AccessToken, &info); err != nil {
		return profile{}, errors.Join(ErrProviderUnavailable, err)
	}
	if info.str("sub") != out.subject {
		return profile{}, ErrInvalidIdentity
	}
	out.email, out.emailVerified = info.str("email"), info.flag("email_verified")
	return out, nil
}
