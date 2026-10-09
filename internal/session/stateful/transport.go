package stateful

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/principal"
)

// HeaderSessionToken carries a new session token in a response under Bearer transport; the client
// presents it back as an Authorization Bearer credential.
const HeaderSessionToken = "X-Egauth-Session-Token"

const (
	headerAuthorization = "Authorization"
	headerCacheControl  = "Cache-Control"
	bearerScheme        = "bearer"
	secretLen           = 32
)

var (
	b64             = base64.RawURLEncoding.Strict()
	errMalformedTok = errors.New("stateful: malformed session token")
)

type presented struct {
	transport core.Transport
	token     string
	bearer    string
	ambiguous bool
}

func (b *Backend) read(r *http.Request) presented {
	bearer := bearerToken(r)
	c, _ := b.cookies.Read(r, cookie.StatefulSession)
	if c == "" {
		return presented{transport: core.TransportBearer, token: bearer}
	}
	return presented{transport: core.TransportCookies, token: c, bearer: bearer, ambiguous: bearer != "" || hasBearerScheme(r)}
}

func (p presented) presented() []string {
	var out []string
	for _, v := range []string{p.token, p.bearer} {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

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

func newToken(t principal.TenantID) (string, []byte, error) {
	secret := make([]byte, secretLen)
	if _, err := rand.Read(secret); err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(secret)
	v := b64.EncodeToString(secret)
	if !t.IsZero() {
		v += "." + t.String()
	}
	return v, sum[:], nil
}

func parseToken(v string) (principal.TenantID, []byte, error) {
	raw, ten, hasTenant := strings.Cut(v, ".")
	secret, err := b64.DecodeString(raw)
	if err != nil || len(secret) != secretLen {
		return principal.TenantID{}, nil, errMalformedTok
	}
	var t principal.TenantID
	if hasTenant {
		if t, err = principal.ParseTenantID(ten); err != nil {
			return principal.TenantID{}, nil, errors.Join(errMalformedTok, err)
		}
	}
	sum := sha256.Sum256(secret)
	return t, sum[:], nil
}

func (b *Backend) write(w http.ResponseWriter, a core.SessionAttrs, tok string, idle time.Time, issued bool) error {
	switch a.Transport() {
	case core.TransportCookies:
		left := idle.Sub(b.clk.Now())
		maxAge := (left + time.Second - 1).Truncate(time.Second)
		return b.cookies.SetSession(w, cookie.StatefulSession, tok, a.RememberMe(), maxAge)
	case core.TransportBearer:
		if !issued {
			return nil
		}
		h := w.Header()
		h.Set(headerCacheControl, "no-store")
		h.Set(HeaderSessionToken, tok)
		return nil
	}
	return errors.Join(core.ErrInvalidArgument, errors.New("stateful: session transport"))
}
