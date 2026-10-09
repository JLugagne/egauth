package federationsvc

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/signing"
)

const (
	clockLeeway       = time.Minute
	jwksTTL           = time.Hour
	jwksMinRefresh    = time.Minute
	maxJWKSEntries    = 256
	maxIDTokenBytes   = 16 << 10
	maxIDTokenHeaders = 1 << 10
	maxUnixSeconds    = 1 << 40
)

type jwsHeader struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Crit json.RawMessage `json:"crit"`
}

func (s *Service) verifyIDToken(ctx context.Context, r resolved, raw, nonce string) (claims, error) {
	p := r.spec
	if len(raw) > maxIDTokenBytes {
		return nil, ErrInvalidIdentity
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidIdentity
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(hb) > maxIDTokenHeaders {
		return nil, ErrInvalidIdentity
	}
	var h jwsHeader
	if err := json.Unmarshal(hb, &h); err != nil || len(h.Crit) > 0 {
		return nil, ErrInvalidIdentity
	}
	switch h.Alg {
	case signing.AlgEdDSA, signing.AlgES256, signing.AlgRS256:
	default:
		return nil, errors.Join(ErrInvalidIdentity, errors.New("id_token algorithm "+h.Alg+" refused"))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidIdentity
	}
	v, err := s.jwks.key(ctx, r.client, p.JWKSURL, h.Kid)
	if err != nil {
		return nil, err
	}
	if err := v.Verify(signing.Signed{Algorithm: h.Alg, KeyID: v.KeyID(), Input: parts[0] + "." + parts[1], Signature: sig}); err != nil {
		return nil, errors.Join(ErrInvalidIdentity, err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidIdentity
	}
	c := claims{}
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return nil, ErrInvalidIdentity
	}
	if err := checkIDClaims(c, p.Issuer, p.ClientID, nonce, s.clock.Now()); err != nil {
		return nil, errors.Join(ErrInvalidIdentity, err)
	}
	return c, nil
}

func checkIDClaims(c claims, issuer, clientID, nonce string, now time.Time) error {
	if c.str("iss") != issuer {
		return errors.New("issuer")
	}
	if c.str("sub") == "" {
		return errors.New("subject")
	}
	aud := audiences(c["aud"])
	found := false
	for _, a := range aud {
		found = found || a == clientID
	}
	if !found {
		return errors.New("audience")
	}
	_, hasAzp := c["azp"]
	if (len(aud) > 1 || hasAzp) && c.str("azp") != clientID {
		return errors.New("authorized party")
	}
	exp, ok := unix(c["exp"])
	if !ok || !now.Before(exp.Add(clockLeeway)) {
		return errors.New("expired")
	}
	iat, ok := unix(c["iat"])
	if !ok || iat.After(now.Add(clockLeeway)) {
		return errors.New("issued in the future")
	}
	got := c.str("nonce")
	if nonce == "" || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return errors.New("nonce")
	}
	return nil
}

func audiences(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func unix(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || f <= 0 || f > maxUnixSeconds {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

type jwksEntry struct {
	keys    []signing.Verifier
	fetched time.Time
}

type jwksCache struct {
	clock   clock.Clock
	mu      sync.Mutex
	entries map[string]jwksEntry
}

func newJWKSCache(c clock.Clock) *jwksCache {
	return &jwksCache{clock: c, entries: map[string]jwksEntry{}}
}

func (c *jwksCache) key(ctx context.Context, d doer, url, kid string) (signing.Verifier, error) {
	now := c.clock.Now()
	c.mu.Lock()
	e, ok := c.entries[url]
	c.mu.Unlock()
	if ok && now.Before(e.fetched.Add(jwksTTL)) {
		if v, found := pick(e.keys, kid); found {
			return v, nil
		}
		if now.Before(e.fetched.Add(jwksMinRefresh)) {
			return signing.Verifier{}, errors.Join(ErrInvalidIdentity, errors.New("unknown key id"))
		}
	}
	keys, err := fetchJWKS(ctx, d, url)
	if err != nil {
		return signing.Verifier{}, errors.Join(ErrProviderUnavailable, err)
	}
	c.mu.Lock()
	if _, present := c.entries[url]; !present && len(c.entries) >= maxJWKSEntries {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[url] = jwksEntry{keys: keys, fetched: now}
	c.mu.Unlock()
	v, found := pick(keys, kid)
	if !found {
		return signing.Verifier{}, errors.Join(ErrInvalidIdentity, errors.New("unknown key id"))
	}
	return v, nil
}

func pick(keys []signing.Verifier, kid string) (signing.Verifier, bool) {
	if kid == "" {
		if len(keys) == 1 {
			return keys[0], true
		}
		return signing.Verifier{}, false
	}
	for _, k := range keys {
		if k.KeyID() == kid {
			return k, true
		}
	}
	return signing.Verifier{}, false
}

func fetchJWKS(ctx context.Context, d doer, url string) ([]signing.Verifier, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("federationsvc: jwks status " + resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	return signing.ParseJWKS(body)
}
