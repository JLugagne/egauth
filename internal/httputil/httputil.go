// Package httputil provides shared HTTP helpers used across egauth handler packages.
// It is internal to the module — nothing outside github.com/JLugagne/egauth may import it.
package httputil

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

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

// OriginMatchesTrusted reports whether the request's Origin (or Referer fallback) matches
// r.Host or an entry in trustedOrigins. An entry may be a bare host ("app.example.com"),
// matched against the request origin's host only, or a scheme-qualified origin
// ("https://app.example.com"), matched against the request origin's scheme AND host — the
// stricter form, since it distinguishes http from https on the same host. Returns false when
// the request carries neither header (or an opaque "null" Origin).
func OriginMatchesTrusted(r *http.Request, trustedOrigins map[string]bool) bool {
	host := RequestOriginHost(r)
	if host == "" {
		return false
	}
	if host == r.Host || trustedOrigins[host] {
		return true
	}
	if full := requestOriginFull(r); full != "" && trustedOrigins[full] {
		return true
	}
	return false
}

// requestOriginFull returns the scheme+host ("https://app.example.com") of the request's
// Origin header, falling back to Referer. Returns "" on the same conditions as
// RequestOriginHost (missing/unparseable header, opaque "null" origin).
func requestOriginFull(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" {
		if o == "null" {
			return ""
		}
		if u, err := url.Parse(o); err == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
		return ""
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}

// RequestOriginHost returns the hostname (host:port) from the request's Origin header, or
// falls back to the Referer header.  Returns "" when neither header is present or parseable,
// and when Origin is the special value "null" (opaque origin).
func RequestOriginHost(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" {
		// A present Origin is authoritative. The opaque "null" origin (sandboxed iframe, some
		// redirect / privacy contexts) is treated as untrusted and does NOT fall back to Referer:
		// a request that declines to assert an origin must not be validated via the weaker,
		// more-spoofable Referer.
		if o == "null" {
			return ""
		}
		if u, err := url.Parse(o); err == nil {
			return u.Host
		}
		return ""
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			return u.Host
		}
	}
	return ""
}

// OriginAllowed reports whether the incoming request comes from a trusted origin.
// When trustedOrigins is empty all origins are allowed (opt-in protection).
// The request's own Host is always considered trusted.
func OriginAllowed(r *http.Request, trustedOrigins map[string]bool) bool {
	if len(trustedOrigins) == 0 {
		return true
	}
	return OriginMatchesTrusted(r, trustedOrigins)
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
