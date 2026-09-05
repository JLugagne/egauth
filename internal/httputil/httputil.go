// Package httputil provides shared HTTP helpers used across egauth handler packages.
// It is internal to the module — nothing outside github.com/JLugagne/egauth may import it.
package httputil

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ClientIP extracts the client IP (host portion) from r.RemoteAddr. It does NOT trust
// X-Forwarded-For or Forwarded headers because egauth cannot know the deployment proxy topology.
func ClientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// WriteJSON writes a JSON-encoded body with the given HTTP status.

func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// WithErrorParam appends (or replaces) the "error" query-string parameter on rawURL.
// If rawURL cannot be parsed, it is returned unchanged.
func WithErrorParam(rawURL, code string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("error", code)
	u.RawQuery = q.Encode()
	return u.String()
}

// RequestOriginURL returns the parsed URL from the request's Origin header, or falls back to
// the Referer header. Returns nil when neither header is present or parseable, when the parsed
// host is empty, or when Origin is the special value "null" (opaque origin).
func RequestOriginURL(r *http.Request) *url.URL {
	if o := r.Header.Get("Origin"); o != "" {
		// A present Origin is authoritative. The opaque "null" origin (sandboxed iframe, some
		// redirect / privacy contexts) is treated as untrusted and does NOT fall back to Referer:
		// a request that declines to assert an origin must not be validated via the weaker,
		// more-spoofable Referer.
		if o == "null" {
			return nil
		}
		if u, err := url.Parse(o); err == nil && u.Host != "" {
			return u
		}
		return nil
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host != "" {
			return u
		}
	}
	return nil
}

// RequestOriginHost returns the hostname (host:port) from the request's Origin header, or
// falls back to the Referer header. Returns "" when neither header is present or parseable,
// when the parsed host is empty, and when Origin is the special value "null" (opaque origin).
func RequestOriginHost(r *http.Request) string {
	if u := RequestOriginURL(r); u != nil {
		return u.Host
	}
	return ""
}

// IsHTTPS reports whether the request was received over HTTPS by inspecting TLS state,
// the request URL scheme, or the X-Forwarded-Proto header.
func IsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if r.URL != nil && strings.EqualFold(r.URL.Scheme, "https") {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		if idx := strings.IndexByte(proto, ','); idx != -1 {
			proto = proto[:idx]
		}
		if strings.EqualFold(strings.TrimSpace(proto), "https") {
			return true
		}
	}
	return false
}

// OriginAllowed reports whether the incoming request comes from a trusted origin.
// A request is allowed only if its origin host matches the request's own Host or is explicitly
// allowlisted in trustedOrigins. When trustedOrigins is empty, only same-host requests are allowed
// (secure by default; foreign origins are rejected).
// Additionally, cross-scheme protection is enforced: if the request is served over HTTPS,
// an Origin or Referer with scheme "http" is rejected.
func OriginAllowed(r *http.Request, trustedOrigins map[string]bool) bool {
	u := RequestOriginURL(r)
	if u == nil || u.Host == "" {
		return false
	}
	if IsHTTPS(r) && strings.EqualFold(u.Scheme, "http") {
		return false
	}
	return u.Host == r.Host || trustedOrigins[u.Host]
}

// Fail writes an error response: it redirects to failureURL (with an ?error= parameter) when
// failureURL is non-empty, otherwise it writes a plain-text HTTP error with the given status.
func Fail(w http.ResponseWriter, r *http.Request, failureURL string, status int, code string) {
	if failureURL != "" {
		http.Redirect(w, r, WithErrorParam(failureURL, code), http.StatusSeeOther)
		return
	}
	http.Error(w, code, status)
}

// ParseLimitedForm limits the request body to maxBodyBytes (when > 0) and parses the form.
// On failure it calls failFn with the appropriate status and error code and returns false.
// Returns true when the form was parsed successfully.
func ParseLimitedForm(w http.ResponseWriter, r *http.Request, maxBodyBytes int64, failFn func(http.ResponseWriter, *http.Request, int, string)) bool {
	if maxBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	}
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			failFn(w, r, http.StatusRequestEntityTooLarge, "request_too_large")
		} else {
			failFn(w, r, http.StatusBadRequest, "invalid_request")
		}
		return false
	}
	return true
}

// RedirectOrStatus redirects to rawURL when it is non-empty, otherwise writes the given HTTP
// status code with no body.
func RedirectOrStatus(w http.ResponseWriter, r *http.Request, rawURL string, okStatus int) {
	if rawURL != "" {
		http.Redirect(w, r, rawURL, http.StatusSeeOther)
		return
	}
	w.WriteHeader(okStatus)
}
