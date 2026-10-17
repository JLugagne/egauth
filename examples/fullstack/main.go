// Package main is a runnable reference application of egauth: password, magic link, passkey, TOTP
// MFA, self-delete and API keys on in-memory storage, composed with New and Routes.
//
// It imports only the egauth module and github.com/google/uuid, and builds with a plain go build.
// Every secret comes from the environment (EGAUTH_KEK, EGAUTH_SIGNING_SEED, 32 bytes each, hex encoded); when unset, a fresh
// random key is generated, which is acceptable only because the storage is in memory and the
// public origin is a loopback origin. The public origin comes from EGAUTH_PUBLIC_ORIGIN, default
// http://localhost:8080, and the listen address is derived from it; the server speaks plain HTTP,
// so only an http loopback origin is accepted.
//
// The email sink logs only the kind of each message: link and code values are redacted by the
// library, so email flows (registration, password reset, magic link) cannot be completed by hand
// against this binary, and no user id is surfaced for EGAUTH_ADMIN_USERS. Replace logEmail with a
// real mailer to use those flows; the tests complete them against a build that captures the mail.
//
// # Routes
//
// The auth endpoints are served by egauth under /auth (see the library documentation). The
// application adds:
//
//	GET  /me                     the caller's subject and role (any established session)
//	POST /admin/disable/{id}     disable an account (admin role and a completed second factor)
//	POST /api/keys               issue an "automation" API key to the caller (?scope= grants a scope)
//	GET  /api/report             an API-key route (kind "automation", scope "report:read")
//	GET  /healthz                readiness probe
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/keys"
)

// AppClaims is the application part of every session's claims.
type AppClaims struct {
	Plan string `json:"plan,omitempty"`
}

type claimsSource struct {
	admins map[uuid.UUID]bool
}

func (c claimsSource) ClaimsFor(_ context.Context, s principal.Subject) (egauth.AppClaims[AppClaims], error) {
	roles := []string{"user"}
	if c.admins[s.User] {
		roles = append(roles, "admin")
	}
	return egauth.AppClaims[AppClaims]{
		Roles:  roles,
		Scopes: []string{"report:read"},
		Custom: AppClaims{Plan: "demo"},
	}, nil
}

type logEmail struct {
	log *slog.Logger
}

func (l logEmail) note(kind string) error {
	l.log.Info("email delivered", "kind", kind)
	return nil
}

func (l logEmail) RegistrationLink(_ context.Context, m egauth.LinkMessage) error {
	return l.note("registration_link")
}

func (l logEmail) AccountExistsNotice(_ context.Context, m egauth.NoticeMessage) error {
	return l.note("account_exists_notice")
}

func (l logEmail) PasswordResetLink(_ context.Context, m egauth.LinkMessage) error {
	return l.note("password_reset_link")
}

func (l logEmail) MagicLink(_ context.Context, m egauth.LinkMessage) error {
	return l.note("magic_link")
}

func (l logEmail) LoginCode(_ context.Context, m egauth.CodeMessage) error {
	return l.note("login_code")
}

func (l logEmail) EmailVerificationLink(_ context.Context, m egauth.LinkMessage) error {
	return l.note("email_verification_link")
}

func (l logEmail) EmailChangeLink(_ context.Context, m egauth.LinkMessage) error {
	return l.note("email_change_link")
}

func (l logEmail) RecoveryEmailLink(_ context.Context, m egauth.LinkMessage) error {
	return l.note("recovery_email_link")
}

func (l logEmail) SecurityNotice(_ context.Context, m egauth.SecurityNoticeMessage) error {
	return l.note("security_notice")
}

func envKey(name string) ([]byte, error) {
	raw := os.Getenv(name)
	if raw == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, errors.Join(errors.New("reading crypto/rand"), err)
		}
		return key, nil
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, errors.Join(errors.New(name+" is not hex"), err)
	}
	return key, nil
}

func adminSubjects() (map[uuid.UUID]bool, error) {
	out := map[uuid.UUID]bool{}
	for _, raw := range strings.Split(os.Getenv("EGAUTH_ADMIN_USERS"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, errors.Join(errors.New("EGAUTH_ADMIN_USERS holds a value that is not a uuid"), err)
		}
		out[id] = true
	}
	return out, nil
}

// BuildServer composes the application on publicOrigin and returns its handler and the function
// that closes it. The handler serves the auth endpoints, the application routes and nothing else.
func BuildServer(logger *slog.Logger, publicOrigin string) (http.Handler, func() error, error) {
	admins, err := adminSubjects()
	if err != nil {
		return nil, nil, err
	}
	return compose(logger, publicOrigin, logEmail{log: logger}, admins)
}

func compose(logger *slog.Logger, publicOrigin string, mailer egauth.EmailDeliverer, admins map[uuid.UUID]bool) (http.Handler, func() error, error) {
	kekKey, err := envKey("EGAUTH_KEK")
	if err != nil {
		return nil, nil, err
	}
	k, err := kek.NewLocal(kekKey)
	if err != nil {
		return nil, nil, err
	}
	seed, err := envKey("EGAUTH_SIGNING_SEED")
	if err != nil {
		return nil, nil, err
	}
	signer, err := signing.EdDSA("k1", seed)
	if err != nil {
		return nil, nil, err
	}
	auth, err := egauth.New(egauth.Config[AppClaims]{
		PublicOrigin: publicOrigin,
		Proxy:        egauth.DirectClients(),
		Storage:      memstore.New(k),
		KEK:          k,
		Sessions:     egauth.JWT(egauth.StaticKeys(signer)),
		Admin:        egauth.RoleAdmin("admin"),
		Claims:       claimsSource{admins: admins},
		Events:       event.NewSlogSink(logger),
		Email:        mailer,
		Pages: egauth.Pages{
			Login: "/login", AfterLogin: "/", MFA: "/mfa", Reauth: "/reauth", Error: "/login",
			ConfirmRegistration: "/register/confirm", PasswordReset: "/reset", MagicLink: "/magic",
			SecurityRevert: "/revert",
		},
		Modules: egauth.Modules{
			Password:   &egauth.PasswordModule{},
			MagicLink:  &egauth.MagicLinkModule{},
			Passkey:    &egauth.PasskeyModule{DisplayName: "egauth demo"},
			MFA:        &egauth.MFAModule{},
			SelfDelete: &egauth.SelfDeleteModule{},
			APIKeys:    &egauth.APIKeyModule{Kinds: []string{"automation"}},
		},
	})
	if err != nil {
		return nil, nil, err
	}
	h, err := auth.Routes().
		Protect("GET /me", me).
		Protect("POST /admin/disable/{id}", adminDisable(auth), egauth.RequireAnyRole("admin"), egauth.RequireMFA()).
		Protect("POST /api/keys", issueKey(auth)).
		ProtectAPI("GET /api/report", report, egauth.Kinds("automation"), egauth.RequireAnyScope("report:read")).
		Public("GET /healthz", healthz(auth)).
		Build()
	if err != nil {
		return nil, nil, errors.Join(err, auth.Close())
	}
	return h, auth.Close, nil
}

func me(w http.ResponseWriter, _ *http.Request, p egauth.Principal[AppClaims]) {
	_, _ = fmt.Fprintf(w, "user=%s roles=%s\n", p.Subject().User, strings.Join(p.Claims().Roles, ","))
}

func issueKey(auth *egauth.Auth[AppClaims]) egauth.PrincipalHandler[AppClaims] {
	return func(w http.ResponseWriter, r *http.Request, p egauth.Principal[AppClaims]) {
		req := egauth.APIKeyRequest{Kind: "automation", Name: "demo", Lifetime: keys.DefaultExpiry()}
		if scope := r.URL.Query().Get("scope"); scope != "" {
			req.Scopes = []string{scope}
		}
		secret, err := auth.APIKeys().Create(r.Context(), p.Caller(), req)
		if err != nil {
			code, msg := disableStatus(err)
			http.Error(w, msg, code)
			return
		}
		_, _ = fmt.Fprint(w, secret.Reveal())
	}
}

func report(w http.ResponseWriter, _ *http.Request, p egauth.Principal[AppClaims]) {
	_, _ = fmt.Fprintf(w, "report for %s\n", p.Subject().User)
}

func adminDisable(auth *egauth.Auth[AppClaims]) egauth.PrincipalHandler[AppClaims] {
	return func(w http.ResponseWriter, r *http.Request, p egauth.Principal[AppClaims]) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		if err := auth.Accounts().Disable(r.Context(), p.Caller(), id); err != nil {
			code, msg := disableStatus(err)
			http.Error(w, msg, code)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func disableStatus(err error) (int, string) {
	switch {
	case errors.Is(err, egauth.ErrForbidden), errors.Is(err, egauth.ErrTenantMismatch), errors.Is(err, egauth.ErrAPIKeyCaller):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, egauth.ErrInvalidRequest):
		return http.StatusBadRequest, "invalid request"
	case errors.Is(err, egauth.ErrReauthRequired):
		return http.StatusUnauthorized, "reauthentication required"
	case errors.Is(err, store.ErrNotFound), errors.Is(err, identity.ErrTombstoned):
		return http.StatusNotFound, "not found"
	}
	return http.StatusInternalServerError, "internal error"
}

func healthz(auth *egauth.Auth[AppClaims]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := auth.Ready(r.Context()); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func listenAddr(publicOrigin string) (string, error) {
	u, err := url.Parse(publicOrigin)
	if err != nil || u.Hostname() == "" {
		return "", errors.Join(errors.New("public origin is not a URL with a host"), err)
	}
	if u.Scheme != "http" {
		return "", errors.New("public origin must be http: this example serves plain HTTP")
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

func main() {
	logger := slog.Default()
	origin := os.Getenv("EGAUTH_PUBLIC_ORIGIN")
	if origin == "" {
		origin = "http://localhost:8080"
	}
	h, closeFn, err := BuildServer(logger, origin)
	if err != nil {
		logger.Error("failed to build server", "err", err)
		os.Exit(1)
	}
	addr, err := listenAddr(origin)
	if err != nil {
		logger.Error("invalid public origin", "err", errors.Join(err, closeFn()))
		os.Exit(1)
	}
	logger.Info("egauth fullstack example listening", "addr", addr, "public_origin", origin)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	serveErr := srv.ListenAndServe()
	logger.Error("server stopped", "err", errors.Join(serveErr, closeFn()))
	os.Exit(1)
}
