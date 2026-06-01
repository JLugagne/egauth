package otp

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// DefaultMaxBodyBytes bounds the request body of the OTP handlers before form parsing.
const DefaultMaxBodyBytes int64 = 4 << 10 // 4 KiB

// handlerConfig holds the configurable behavior of the OTP HTTP handlers.
type handlerConfig struct {
	subjectResolver func(*http.Request) (uuid.UUID, bool)
	purpose         string
	purposeResolver func(*http.Request) string
	codeField       string
	tenantResolver  func(*http.Request) string
	trustedOrigins  map[string]bool
	maxBodyBytes    int64
	successURL      string
	failureURL      string
	onVerified      func(w http.ResponseWriter, r *http.Request, subjectID uuid.UUID)
}

// HandlerOption configures the OTP HTTP handlers (IssueHandler, VerifyHandler).
type HandlerOption func(*handlerConfig)

func newHandlerConfig(opts []HandlerOption) handlerConfig {
	c := handlerConfig{
		codeField:    "code",
		purpose:      "login",
		maxBodyBytes: DefaultMaxBodyBytes,
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// WithSubjectResolver supplies the subject (e.g. user ID) an OTP challenge belongs to. The
// application maps the request (an authenticated session, or a submitted email) to a subject
// ID, returning ok=false when it cannot — handlers then respond uniformly so they leak no
// account-existence signal. It is required; without it the handlers respond 401.
func WithSubjectResolver(f func(*http.Request) (uuid.UUID, bool)) HandlerOption {
	return func(h *handlerConfig) { h.subjectResolver = f }
}

// WithPurpose sets the fixed challenge purpose (default "login").
func WithPurpose(purpose string) HandlerOption {
	return func(h *handlerConfig) { h.purpose = purpose }
}

// WithPurposeResolver derives the purpose from the request (overrides WithPurpose when set).
func WithPurposeResolver(f func(*http.Request) string) HandlerOption {
	return func(h *handlerConfig) { h.purposeResolver = f }
}

// WithCodeField overrides the form field carrying the code in VerifyHandler (default "code").
func WithCodeField(name string) HandlerOption {
	return func(h *handlerConfig) { h.codeField = name }
}

// WithTenantResolver derives the tenant from the request to scope store operations.
func WithTenantResolver(f func(*http.Request) string) HandlerOption {
	return func(h *handlerConfig) { h.tenantResolver = f }
}

// WithTrustedOrigins enables a CSRF Origin/Referer allowlist check (see the identity/tokens
// handlers). Disabled when unset.
func WithTrustedOrigins(origins ...string) HandlerOption {
	return func(h *handlerConfig) {
		h.trustedOrigins = make(map[string]bool, len(origins))
		for _, o := range origins {
			h.trustedOrigins[o] = true
		}
	}
}

// WithMaxBodyBytes overrides the request-body cap (default DefaultMaxBodyBytes). Non-positive
// disables it.
func WithMaxBodyBytes(n int64) HandlerOption {
	return func(h *handlerConfig) { h.maxBodyBytes = n }
}

// WithSuccessRedirect replies with a 303 redirect to url on success instead of 204.
func WithSuccessRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.successURL = url }
}

// WithFailureRedirect replies with a 303 redirect to url (carrying ?error=<code>) on failure.
func WithFailureRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.failureURL = url }
}

// WithOnVerified runs after a successful verification (e.g. to issue a session/token pair). It
// owns the response when set; otherwise the handler replies 204 / the success redirect.
func WithOnVerified(f func(w http.ResponseWriter, r *http.Request, subjectID uuid.UUID)) HandlerOption {
	return func(h *handlerConfig) { h.onVerified = f }
}

// IssueHandler builds an HTTP handler that mints an OTP for the resolved subject and hands the
// Challenge (including the plaintext code) to deliver for out-of-band delivery (email/SMS).
// It ALWAYS responds uniformly (204 / success redirect) — whether or not a subject was
// resolved or delivery succeeded — so it leaks no account-existence signal, and dispatches
// delivery off the response path to avoid a timing oracle.
func IssueHandler(svc Service, deliver func(ctx context.Context, ch *Challenge) error, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !cfg.originAllowed(r) {
			cfg.fail(w, r, http.StatusForbidden, "cross_site_blocked")
			return
		}
		if cfg.subjectResolver == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		if subjectID, ok := cfg.subjectResolver(r); ok {
			if ch, err := svc.Issue(r.Context(), cfg.tenant(r), subjectID, cfg.purposeOf(r)); err == nil && deliver != nil {
				ctx := context.WithoutCancel(r.Context())
				go func() { _ = deliver(ctx, ch) }()
			}
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// VerifyHandler builds an HTTP handler that verifies a presented OTP for the resolved subject.
// Every failure — wrong code, no/expired challenge, or too many attempts — is collapsed into a
// single 401 "invalid_code" response, so a client cannot tell a wrong guess from a missing
// challenge from a burned one (challenge enumeration). On success it runs WithOnVerified (if
// set) or replies 204 / the success redirect.
func VerifyHandler(svc Service, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !cfg.originAllowed(r) {
			cfg.fail(w, r, http.StatusForbidden, "cross_site_blocked")
			return
		}
		if cfg.subjectResolver == nil {
			cfg.fail(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !cfg.parseLimitedForm(w, r) {
			return
		}

		subjectID, ok := cfg.subjectResolver(r)
		code := r.PostForm.Get(cfg.codeField)
		// Uniform rejection for an unresolved subject or any verify failure.
		if !ok {
			cfg.fail(w, r, http.StatusUnauthorized, "invalid_code")
			return
		}
		if err := svc.Verify(r.Context(), cfg.tenant(r), subjectID, cfg.purposeOf(r), code); err != nil {
			cfg.fail(w, r, http.StatusUnauthorized, "invalid_code")
			return
		}

		if cfg.onVerified != nil {
			cfg.onVerified(w, r, subjectID)
			return
		}
		redirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

func (cfg handlerConfig) purposeOf(r *http.Request) string {
	if cfg.purposeResolver != nil {
		return cfg.purposeResolver(r)
	}
	return cfg.purpose
}

// tenant returns the tenant derived from the request's resolver, or "" when no resolver is
// configured (the single-tenant default partition).
func (cfg handlerConfig) tenant(r *http.Request) string {
	if cfg.tenantResolver == nil {
		return ""
	}
	return cfg.tenantResolver(r)
}

func (cfg handlerConfig) parseLimitedForm(w http.ResponseWriter, r *http.Request) bool {
	if cfg.maxBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, cfg.maxBodyBytes)
	}
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			cfg.fail(w, r, http.StatusRequestEntityTooLarge, "request_too_large")
		} else {
			cfg.fail(w, r, http.StatusBadRequest, "invalid_request")
		}
		return false
	}
	return true
}

func (cfg handlerConfig) originAllowed(r *http.Request) bool {
	if len(cfg.trustedOrigins) == 0 {
		return true
	}
	host := requestOriginHost(r)
	if host == "" {
		return false
	}
	return host == r.Host || cfg.trustedOrigins[host]
}

func requestOriginHost(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
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

func (cfg handlerConfig) fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	if cfg.failureURL != "" {
		http.Redirect(w, r, withErrorParam(cfg.failureURL, code), http.StatusSeeOther)
		return
	}
	http.Error(w, code, status)
}

func redirectOrStatus(w http.ResponseWriter, r *http.Request, url string, okStatus int) {
	if url != "" {
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}
	w.WriteHeader(okStatus)
}

func withErrorParam(rawURL, code string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("error", code)
	u.RawQuery = q.Encode()
	return u.String()
}
