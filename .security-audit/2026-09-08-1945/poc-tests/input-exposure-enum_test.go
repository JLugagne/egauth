package zzauditpoc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Security-audit PoCs (input-exposure): mass assignment, body limits, IDOR/tenant
// cross-access, normalization, enumeration oracle. No external hosts.

func auditIssuer() *issuertest.MockIssuer[struct{}] {
	return &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			return &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", Claims: claims}, nil
		},
	}
}

func auditClaims(u *identity.User) tokens.Claims[struct{}] {
	return tokens.Claims[struct{}]{Subject: u.ID, TenantID: u.TenantID}
}

func auditForm(path string, values url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

type auditPolicy struct{}

func (a *auditPolicy) Verify(ctx context.Context, password string) error { return nil }

// TestAuditMassAssignment_PrivilegedFieldsIgnored proves a hostile register form carrying
// privileged fields (tenant_id, roles, scopes, verified flags) cannot over-bind: the
// handler only reads email/password (+remember) and the tenant comes from the
// server-side resolver, never the body.
func TestAuditMassAssignment_PrivilegedFieldsIgnored(t *testing.T) {
	var gotTenant, gotEmail string
	svc := &servicetest.MockService{
		RegisterFunc: func(ctx context.Context, tenantID, email, password string) (*identity.User, error) {
			gotTenant, gotEmail = tenantID, email
			return &identity.User{ID: uuid.Must(uuid.NewV7()), TenantID: tenantID, Email: email}, nil
		},
	}
	h := identity.RegisterHandler[struct{}](svc, auditIssuer(), auditClaims,
		identity.WithTenantResolver(func(r *http.Request) string { return "tenant-legit" }))

	form := url.Values{}
	form.Set("email", "victim@example.com")
	form.Set("password", "SuperSecret123!")
	form.Set("tenant_id", "tenant-attacker")
	form.Set("TenantID", "tenant-attacker")
	form.Set("roles", "admin")
	form.Set("scopes", "admin:all")
	form.Set("email_verified_at", "2020-01-01T00:00:00Z")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, auditForm("/register", form))

	require.Equal(t, http.StatusNoContent, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "tenant-legit", gotTenant, "tenant must come from resolver, not body")
	assert.Equal(t, "victim@example.com", gotEmail)
}

// TestAuditBodyLimit_OversizedRegisterRejected proves the 4 KiB body cap replies 413 and
// never invokes the service (pre-auth KDF amplification guard).
func TestAuditBodyLimit_OversizedRegisterRejected(t *testing.T) {
	called := false
	svc := &servicetest.MockService{
		RegisterFunc: func(ctx context.Context, tenantID, email, password string) (*identity.User, error) {
			called = true
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.RegisterHandler[struct{}](svc, auditIssuer(), auditClaims)

	huge := strings.Repeat("a", int(identity.DefaultMaxBodyBytes)+(1<<10))
	form := url.Values{}
	form.Set("email", "u@example.com")
	form.Set("password", huge)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, auditForm("/register", form))

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.False(t, called, "service must not run for over-limit bodies")
}

// TestAuditIDOR_VerificationTokenCrossTenant proves a token minted in tenant A cannot be
// consumed under tenant B at the data layer (memory store).
func TestAuditIDOR_VerificationTokenCrossTenant(t *testing.T) {
	ctx := context.Background()
	store := identitymemory.NewStore()
	user, err := store.CreateUser(ctx, "tenant-a", "a@example.com")
	require.NoError(t, err)

	token, err := store.CreateVerificationToken(ctx, "tenant-a", user.ID, "password_reset", time.Hour, nil)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	_, _, err = store.ConsumeVerificationToken(ctx, "tenant-b", token, "password_reset")
	require.Error(t, err, "cross-tenant token consume must fail")

	_, err = store.FindUserByID(ctx, "tenant-b", user.ID)
	require.Error(t, err, "cross-tenant user lookup must fail")
}

// TestAuditNormalization_CaseVariantDuplicate proves a case/whitespace variant of an
// existing email cannot pre-register a shadow account.
func TestAuditNormalization_CaseVariantDuplicate(t *testing.T) {
	ctx := context.Background()
	hasher := &hashertest.MockHasher{HashFunc: func(ctx context.Context, p string) (string, error) { return "h", nil }}
	svc := identity.NewService(identitymemory.NewStore(), hasher, &auditPolicy{})

	_, err := svc.Register(ctx, "", "  User@Example.COM ", "pw")
	require.NoError(t, err)
	_, err = svc.Register(ctx, "", "user@example.com", "pw")
	assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)
}

// TestAuditEnumeration_DisabledVsUnknown demonstrates the message oracle: with default
// options (no WithUniformAuthErrors) a disabled account answers 429 account_locked while
// an unknown account answers 401 invalid_credentials — a single-shot existence oracle
// for disabled accounts (timing is equalized by the decoy hash; status/message is not).
func TestAuditEnumeration_DisabledVsUnknown(t *testing.T) {
	ctx := context.Background()
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{
		HashFunc:    func(ctx context.Context, p string) (string, error) { return "h:" + p, nil },
		CompareFunc: func(ctx context.Context, hash, password string) error { return nil },
	}
	svc := identity.NewService(store, hasher, &auditPolicy{})

	user, err := svc.Register(ctx, "", "disabled@example.com", "pw")
	require.NoError(t, err)
	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	h := identity.LoginHandler[struct{}](svc, auditIssuer(), auditClaims)

	disabledForm := url.Values{}
	disabledForm.Set("email", "disabled@example.com")
	disabledForm.Set("password", "wrong-guess")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, auditForm("/login", disabledForm))
	disabledCode, disabledBody := rec.Code, rec.Body.String()

	unknownForm := url.Values{}
	unknownForm.Set("email", "nobody-knows-this@example.com")
	unknownForm.Set("password", "wrong-guess")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, auditForm("/login", unknownForm))

	t.Logf("disabled account -> %d %q; unknown account -> %d %q",
		disabledCode, disabledBody, rec2.Code, rec2.Body.String())
	assert.Equal(t, http.StatusTooManyRequests, disabledCode)
	assert.Equal(t, http.StatusUnauthorized, rec2.Code)
}
