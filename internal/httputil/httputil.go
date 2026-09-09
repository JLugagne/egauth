// Package httputil provides shared HTTP helpers used across egauth handler packages.
// It is internal to the module — nothing outside github.com/JLugagne/egauth may import it.
package httputil

import (
	"encoding/json"
	"errors"
	"fmt"
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
	MarkNoStore(w)
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
	MarkNoStore(w)
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
	MarkNoStore(w)
	if rawURL != "" {
		http.Redirect(w, r, rawURL, http.StatusSeeOther)
		return
	}
	w.WriteHeader(okStatus)
}

// MarkNoStore marks the response uncacheable: Cache-Control: no-store paired with the legacy
// Pragma: no-cache. The shared response helpers (WriteJSON, Fail, RedirectOrStatus) and every
// token/session-cookie write in the module call it, because auth-flow responses (login,
// register, refresh, logout, OAuth callback, MFA/OTP/passkey/authflow handlers, auto-refresh)
// routinely carry Set-Cookie headers holding live token material: OWASP session-management
// guidance requires such responses to be uncacheable, and RFC 9111 §3.2 lets shared caches
// store Set-Cookie responses unless explicitly barred. Only the auth handler packages use
// these helpers, so the policy is scoped to auth endpoints by construction — unrelated
// packages keep full control of their own caching headers. Callers may still override the
// header afterwards (Header().Set is last-write-wins); the helper only installs the safe
// default. Must be invoked before any WriteHeader/redirect, since header writes after the
// first byte are dropped. Idempotent: repeated calls overwrite the same two headers.
func MarkNoStore(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}

// NormalizeHosts normalizes trusted-origin entries to the bare hosts that OriginAllowed
// matches on. Each entry may be a full origin ("https://app.example.com:8443") or a bare
// host ("app.example.com"): full origins are reduced to their URL Host (host or host:port,
// lowercased by url.Parse, with scheme, path, query and userinfo dropped), and bare-host
// entries are validated and returned as-is. The result is suitable both for the
// WithTrustedOrigins options and for comparison with an Origin header's host. It returns
// an error naming the first entry that fails to parse or yields no host.
func NormalizeHosts(entries []string) ([]string, error) {
	hosts := make([]string, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		host, err := originHost(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid host entry %q: %w", entry, err)
		}
		// Hostnames are case-insensitive, and OriginAllowed compares hosts exactly, so the
		// allowlist is stored lowercase to match the lowercase Origin headers browsers send.
		hosts = append(hosts, strings.ToLower(host))
	}
	return hosts, nil
}

// originHost extracts the host from one allowlist entry. A full origin parses with a
// non-empty Host and is returned as-is; a bare host parses as a path (or scheme:opaque,
// e.g. "app.example.com:8443"), so it is re-validated by re-parsing with a default scheme
// and only accepted when the result is an unambiguous bare host.
func originHost(entry string) (string, error) {
	if entry == "" {
		return "", errors.New("empty entry")
	}
	u, err := url.Parse(entry)
	if err != nil {
		return "", err
	}
	if u.Host != "" {
		return u.Host, nil
	}
	u, err = url.Parse("https://" + entry)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", errors.New("no host")
	}
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("not a bare host")
	}
	return u.Host, nil
}
