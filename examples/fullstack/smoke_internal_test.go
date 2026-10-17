package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
)

func TestJourneyBatteryAgainstBuildServer(t *testing.T) {
	journeytest.RunAgainst(t, BuildServer)
}

func build(t *testing.T) http.Handler {
	t.Helper()
	h, closeFn, err := BuildServer(slog.New(slog.NewTextHandler(io.Discard, nil)), journeytest.ExampleOrigin)
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	t.Cleanup(func() { _ = closeFn() })
	return h
}

func TestDeclaredRoutesRefuseAnonymousCallers(t *testing.T) {
	h := build(t)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/me", http.StatusUnauthorized},
		{http.MethodPost, "/admin/disable/00000000-0000-0000-0000-000000000001", http.StatusUnauthorized},
		{http.MethodGet, "/api/report", http.StatusUnauthorized},
		{http.MethodGet, "/healthz", http.StatusNoContent},
		{http.MethodGet, "/nowhere", http.StatusNotFound},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, journeytest.ExampleOrigin+tc.path, nil)
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestListenAddrIsDerivedFromAnHTTPLoopbackOrigin(t *testing.T) {
	for origin, want := range map[string]string{
		"http://localhost:8080": "localhost:8080",
		"http://localhost:9000": "localhost:9000",
		"http://localhost":      "localhost:80",
	} {
		got, err := listenAddr(origin)
		if err != nil {
			t.Fatalf("%s: %v", origin, err)
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", origin, got, want)
		}
	}
}

func TestListenAddrRefusesAnOriginTheServerCannotServe(t *testing.T) {
	for _, origin := range []string{
		"", "localhost", "ftp://example.com", "http://",
		"https://localhost:8443", "https://auth.example.com",
	} {
		if _, err := listenAddr(origin); err == nil {
			t.Errorf("%q: want an error", origin)
		}
	}
}

func TestBuildServerRefusesAnOriginTheLibraryRefuses(t *testing.T) {
	for _, origin := range []string{
		"http://127.0.0.1:9000", "http://[::1]:8080", "http://localhost:8080/app", "http://localhost:8080?x=1",
		"http://u:p@localhost:8080", "http://localhost:8080#frag", "http://localhost:0", "http://localhost:99999",
		"http://auth.example.com:8080",
	} {
		h, closeFn, err := BuildServer(slog.New(slog.NewTextHandler(io.Discard, nil)), origin)
		if err == nil {
			_ = closeFn()
			t.Errorf("%q: want an error", origin)
		}
		if h != nil {
			t.Errorf("%q: want no handler", origin)
		}
	}
}

func TestDisableStatusSeparatesDenialFromFailure(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{egauth.ErrForbidden, http.StatusForbidden},
		{egauth.ErrTenantMismatch, http.StatusForbidden},
		{egauth.ErrReauthRequired, http.StatusUnauthorized},
		{store.ErrNotFound, http.StatusNotFound},
		{egauth.ErrInvalidRequest, http.StatusBadRequest},
		{errors.New("connection reset"), http.StatusInternalServerError},
	} {
		if got, _ := disableStatus(tc.err); got != tc.want {
			t.Errorf("%v: got %d, want %d", tc.err, got, tc.want)
		}
	}
}

func TestBuildServerRefusesAMalformedAdminList(t *testing.T) {
	t.Setenv("EGAUTH_ADMIN_USERS", "not-a-uuid")
	if _, _, err := BuildServer(slog.Default(), journeytest.ExampleOrigin); err == nil {
		t.Fatal("want an error")
	}
}

func TestBuildServerRefusesAMalformedKey(t *testing.T) {
	t.Setenv("EGAUTH_KEK", "zz")
	if _, _, err := BuildServer(slog.Default(), journeytest.ExampleOrigin); err == nil {
		t.Fatal("want an error")
	}
}

func TestClaimsSourceGrantsAdminOnlyToListedUsers(t *testing.T) {
	admin, other := uuid.New(), uuid.New()
	src := claimsSource{admins: map[uuid.UUID]bool{admin: true}}
	got, err := src.ClaimsFor(context.Background(), principal.Subject{User: admin})
	if err != nil || !slices.Contains(got.Roles, "admin") {
		t.Fatalf("listed user: %v %v", got.Roles, err)
	}
	got, err = src.ClaimsFor(context.Background(), principal.Subject{User: other})
	if err != nil || slices.Contains(got.Roles, "admin") {
		t.Fatalf("other user: %v %v", got.Roles, err)
	}
}

func TestAdminSubjectsParsesTheEnvironment(t *testing.T) {
	id := uuid.New()
	t.Setenv("EGAUTH_ADMIN_USERS", id.String()+" , ")
	admins, err := adminSubjects()
	if err != nil || !admins[id] || len(admins) != 1 {
		t.Fatalf("adminSubjects: %v %v", admins, err)
	}
}
