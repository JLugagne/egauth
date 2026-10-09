package jwt

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/tokens"
)

const (
	// HeaderAccessToken carries a new access token in a response under Bearer transport.
	HeaderAccessToken = "X-Egauth-Access-Token"
	// HeaderRefreshToken carries a new refresh token in a response under Bearer transport, and the
	// refresh token a Bearer client presents to renew. A custom header forces a CORS preflight.
	HeaderRefreshToken = "X-Egauth-Refresh-Token"
	// MaxCookieBytes is the browser limit on a cookie's name and value together. A cookie-transport
	// token pair that would exceed it is refused with core.ErrClaimsTooLarge, never truncated or
	// written for the browser to drop.
	MaxCookieBytes = 4096

	headerAuthorization = "Authorization"
	headerUserAgent     = "User-Agent"
	headerCacheControl  = "Cache-Control"
	bearerScheme        = "bearer"
	handleLen           = 32
	fingerprintLen      = 16
	fingerprintDomain   = "egauth/refresh-client/v1\x00"
)

var errMalformedRefresh = errors.New("jwt: malformed refresh token")

type presented struct {
	transport core.Transport
	access    string
	refresh   string
	ambiguous bool
}

func (b *Backend) read(r *http.Request) presented {
	bearer := presented{transport: core.TransportBearer, access: bearerToken(r), refresh: singleHeader(r, HeaderRefreshToken)}
	a, _ := b.cookies.Read(r, cookie.AccessToken)
	f, _ := b.cookies.Read(r, cookie.RefreshToken)
	if a == "" && f == "" {
		return bearer
	}
	ambiguous := !bearer.empty() || hasBearerScheme(r) || len(r.Header.Values(HeaderRefreshToken)) > 0
	return presented{transport: core.TransportCookies, access: a, refresh: f, ambiguous: ambiguous}
}

func (p presented) empty() bool { return p.access == "" && p.refresh == "" }

func singleHeader(r *http.Request, name string) string {
	vs := r.Header.Values(name)
	if len(vs) != 1 {
		return ""
	}
	return strings.TrimSpace(vs[0])
}

func hasBearerScheme(r *http.Request) bool {
	for _, v := range r.Header.Values(headerAuthorization) {
		scheme, _, _ := strings.Cut(strings.TrimSpace(v), " ")
		if strings.EqualFold(scheme, bearerScheme) {
			return true
		}
	}
	return false
}

func bearerToken(r *http.Request) string {
	scheme, tok, ok := strings.Cut(singleHeader(r, headerAuthorization), " ")
	if !ok || !strings.EqualFold(scheme, bearerScheme) {
		return ""
	}
	tok = strings.TrimSpace(tok)
	if strings.ContainsAny(tok, " \t") {
		return ""
	}
	return tok
}

func clientFingerprint(r *http.Request) []byte {
	sum := sha256.Sum256([]byte(fingerprintDomain + r.Header.Get(headerUserAgent)))
	return sum[:fingerprintLen]
}

func newRefresh(t principal.TenantID) (string, []byte, error) {
	h := make([]byte, handleLen)
	if _, err := rand.Read(h); err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(h)
	v := b64.EncodeToString(h)
	if !t.IsZero() {
		v += "." + t.String()
	}
	return v, sum[:], nil
}

func parseRefresh(v string) (principal.TenantID, []byte, error) {
	raw, ten, hasTenant := strings.Cut(v, ".")
	h, err := b64.DecodeString(raw)
	if err != nil || len(h) != handleLen {
		return principal.TenantID{}, nil, errMalformedRefresh
	}
	var t principal.TenantID
	if hasTenant {
		if t, err = principal.ParseTenantID(ten); err != nil {
			return principal.TenantID{}, nil, errors.Join(errMalformedRefresh, err)
		}
	}
	sum := sha256.Sum256(h)
	return t, sum[:], nil
}

func (b *Backend) fits(a core.SessionAttrs, access, refresh string) error {
	if a.Transport() != core.TransportCookies {
		return nil
	}
	for n, v := range map[cookie.Name]string{cookie.AccessToken: access, cookie.RefreshToken: refresh} {
		if len(b.cookies.CookieName(n))+1+len(v) >= MaxCookieBytes {
			return errors.Join(core.ErrClaimsTooLarge, errors.New("jwt: the session would not fit a browser cookie"))
		}
	}
	return nil
}

func (b *Backend) write(w http.ResponseWriter, a core.SessionAttrs, access, refresh string, rec tokens.RefreshRecord) error {
	switch a.Transport() {
	case core.TransportCookies:
		left := rec.IdleExpiresAt().Sub(b.clk.Now())
		maxAge := (left + time.Second - 1).Truncate(time.Second)
		if err := b.cookies.SetSession(w, cookie.AccessToken, access, a.RememberMe(), maxAge); err != nil {
			return err
		}
		return b.cookies.SetSession(w, cookie.RefreshToken, refresh, a.RememberMe(), maxAge)
	case core.TransportBearer:
		h := w.Header()
		h.Set(headerCacheControl, "no-store")
		h.Set(HeaderAccessToken, access)
		h.Set(HeaderRefreshToken, refresh)
		return nil
	}
	return errors.Join(core.ErrInvalidArgument, errors.New("jwt: session transport"))
}

func (b *Backend) clear(w http.ResponseWriter, r *http.Request, p presented) {
	if p.transport == core.TransportCookies || cookie.Present(r) {
		b.cookies.Clear(w, cookie.AccessToken)
		b.cookies.Clear(w, cookie.RefreshToken)
	}
}
