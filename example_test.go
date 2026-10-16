package egauth_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	"github.com/JLugagne/egauth/store"
)

type inbox struct{ links chan string }

func (m inbox) RegistrationLink(_ context.Context, msg egauth.LinkMessage) error {
	m.links <- msg.Link
	return nil
}
func (inbox) AccountExistsNotice(context.Context, egauth.NoticeMessage) error { return nil }
func (inbox) PasswordResetLink(context.Context, egauth.LinkMessage) error     { return nil }
func (inbox) MagicLink(context.Context, egauth.LinkMessage) error             { return nil }
func (inbox) LoginCode(context.Context, egauth.CodeMessage) error             { return nil }
func (inbox) EmailVerificationLink(context.Context, egauth.LinkMessage) error { return nil }
func (inbox) EmailChangeLink(context.Context, egauth.LinkMessage) error       { return nil }
func (inbox) RecoveryEmailLink(context.Context, egauth.LinkMessage) error     { return nil }
func (inbox) SecurityNotice(context.Context, egauth.SecurityNoticeMessage) error {
	return nil
}

func ExampleNew() {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	k, _ := kek.NewLocal(key)
	signer, _ := signing.EdDSA("k1", seed)
	mail := inbox{links: make(chan string, 1)}

	auth, err := egauth.New(egauth.Config[struct{}]{
		PublicOrigin: "http://localhost:8080",
		Proxy:        egauth.DirectClients(),
		Storage:      memstore.New(k),
		KEK:          k,
		Sessions:     egauth.JWT(egauth.StaticKeys(signer)),
		Transport:    egauth.Bearer,
		Admin:        egauth.RoleAdmin("admin"),
		Email:        mail,
		Pages:        egauth.Pages{Login: "/login", AfterLogin: "/", ConfirmRegistration: "/confirm", PasswordReset: "/reset", SecurityRevert: "/revert"},
		Modules:      egauth.Modules{Password: &egauth.PasswordModule{}},
	})
	if err != nil {
		fmt.Println("new:", err)
		return
	}
	defer func() { _ = auth.Close() }()

	h, err := auth.Routes().
		Protect("GET /me", func(w http.ResponseWriter, _ *http.Request, _ egauth.Principal[struct{}]) {
			_, _ = fmt.Fprintln(w, "hello")
		}).
		Build()
	if err != nil {
		fmt.Println("routes:", err)
		return
	}

	call := func(method, path, token string, body map[string]any, hdr ...string) (*httptest.ResponseRecorder, map[string]any) {
		var payload strings.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			payload = *strings.NewReader(string(raw))
		}
		req := httptest.NewRequest(method, "http://localhost:8080"+path, &payload)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Origin", "http://localhost:8080")
		req.Header.Set(egauth.HeaderTransport, "bearer")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}

	const email, password = "ada@example.com", "tapir-granite-velvet-orbit-29"
	rec, begin := call("POST", "/auth"+egauth.PathRegister, "", map[string]any{egauth.FieldIdentifier: email, egauth.FieldPassword: password})
	fmt.Println("register:", rec.Code)

	link, _ := url.Parse(<-mail.links)
	bind, _ := begin[egauth.FieldBind].(string)
	rec, _ = call("POST", "/auth"+egauth.PathRegisterConfirm, "", map[string]any{egauth.FieldToken: link.Query().Get(egauth.FieldToken), egauth.FieldBind: bind})
	fmt.Println("confirm:", rec.Code)

	rec, _ = call("POST", "/auth"+egauth.PathLogin, "", map[string]any{egauth.FieldIdentifier: email, egauth.FieldPassword: password})
	access, refresh := rec.Header().Get("X-Egauth-Access-Token"), rec.Header().Get("X-Egauth-Refresh-Token")
	fmt.Println("login:", rec.Code)

	rec, _ = call("GET", "/me", access, nil)
	fmt.Println("me:", rec.Code)

	rec, _ = call("POST", "/auth"+egauth.PathRefresh, "", nil, "X-Egauth-Refresh-Token", refresh)
	access, refresh = rec.Header().Get("X-Egauth-Access-Token"), rec.Header().Get("X-Egauth-Refresh-Token")
	fmt.Println("refresh:", rec.Code)

	rec, _ = call("POST", "/auth"+egauth.PathLogout, access, nil)
	fmt.Println("logout:", rec.Code)

	rec, _ = call("POST", "/auth"+egauth.PathRefresh, "", nil, "X-Egauth-Refresh-Token", refresh)
	fmt.Println("refresh after logout:", rec.Code)
	// Output:
	// register: 202
	// confirm: 200
	// login: 200
	// me: 200
	// refresh: 200
	// logout: 200
	// refresh after logout: 401
}

func ExampleRoutes() {
	var auth *egauth.Auth[struct{}]
	var page, report, adminDisable egauth.PrincipalHandler[struct{}]
	var health http.Handler

	h, err := auth.Routes().
		Optional("GET /", page).
		Protect("POST /admin/disable/{id}", adminDisable,
			egauth.RequireAnyRole("admin"), egauth.RequireMFA(), egauth.RequireFreshAuth(egauth.Fresh5m)).
		ProtectAPI("GET /api/report", report, egauth.Kinds("automation"), egauth.RequireAnyScope("report:read")).
		Public("GET /healthz", health).
		Build()
	if err != nil {
		return
	}
	_ = http.ListenAndServe("localhost:8080", h)
}

func ExampleUpgradeSecretsV016() {
	ctx := context.Background()
	var storage egauth.Storage
	var oldKey, newKey []byte

	legacy, err := kek.LegacyLocalV016(oldKey)
	if err != nil {
		return
	}
	current, err := kek.NewLocal(newKey)
	if err != nil {
		return
	}
	report, err := egauth.UpgradeSecretsV016(ctx, storage, legacy, current)
	if err != nil {
		return
	}
	fmt.Println(report)
}

func ExampleUpgradeIdentifiersV016() {
	ctx := context.Background()
	var storage egauth.Storage

	report, err := egauth.UpgradeIdentifiersV016(ctx, storage)
	switch {
	case errors.Is(err, egauth.ErrIdentifiersHeld):
		for _, h := range report.Held {
			fmt.Println("repair by hand:", h.Subject, h.Kind, h.Problem)
		}
	case err != nil:
		return
	}
	fmt.Println(report.Upgraded, report.Rewritten)
}

func ExampleAccounts() {
	ctx := context.Background()
	var auth *egauth.Auth[struct{}]
	var admin principal.Caller
	var user uuid.UUID

	if err := auth.Accounts().Disable(ctx, admin, user); err != nil {
		if errors.Is(err, egauth.ErrForbidden) || errors.Is(err, store.ErrNotFound) {
			return
		}
	}
}
