package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/stretchr/testify/require"
)

// auditHasher is a fast deterministic stand-in for Argon2id: it preserves the
// success/failure semantics Authenticate depends on (including the lockout
// increment path) without the KDF cost.
func auditHasher() *hashertest.MockHasher {
	return &hashertest.MockHasher{
		HashFunc: func(_ context.Context, password string) (string, error) {
			return "audit-hash:" + password, nil
		},
		CompareFunc: func(_ context.Context, hash, password string) error {
			if hash == "audit-hash:"+password {
				return nil
			}
			return passwords.ErrInvalidPassword
		},
	}
}

func auditPolicy() *mockPolicy {
	return &mockPolicy{VerifyFunc: func(context.Context, string) error { return nil }}
}

func auditLoginStatus(h func(w http.ResponseWriter, r *http.Request), t *testing.T, email, password string) int {
	t.Helper()
	req := loginForm(t, "/auth/login", email, password, "")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Code
}

// TestAuditPoc_LockoutStatusOracle demonstrates that the DEFAULT LoginHandler
// leaks account existence/lockout state via the status code: an account the
// attacker managed to lock answers 429 while an unknown identifier answers 401.
// Attacker-controlled input: the login email + password form fields.
func TestAuditPoc_LockoutStatusOracle(t *testing.T) {
	ctx := context.Background()
	svc := identity.NewService(identitymemory.NewStore(), auditHasher(), auditPolicy(),
		identity.WithLockout(3, time.Minute))
	_, err := svc.Register(ctx, "", "victim@example.com", "SomeStrongPassword123!")
	require.NoError(t, err)

	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder())

	const unknown = "nobody-here@example.com"
	require.Equal(t, 401, auditLoginStatus(h.ServeHTTP, t, unknown, "wrong"),
		"unknown account must be 401")

	// Three wrong passwords: still uniform 401s (below threshold).
	for i := 0; i < 3; i++ {
		require.Equal(t, 401, auditLoginStatus(h.ServeHTTP, t, "victim@example.com", "wrong"))
	}
	// The account is now locked: the NEXT attempt answers 429, while the
	// unknown identifier still answers 401 — a remotely observable oracle.
	require.Equal(t, 429, auditLoginStatus(h.ServeHTTP, t, "victim@example.com", "wrong"),
		"VULNERABILITY DEMONSTRATED: locked account answers 429")
	require.Equal(t, 401, auditLoginStatus(h.ServeHTTP, t, unknown, "wrong"),
		"unknown account still answers 401 — the 429/401 gap is an enumeration oracle")
}

// TestAuditPoc_DisabledStatusOracle demonstrates the same oracle without any
// prior interaction: an administratively disabled account answers 429 on the
// very first login attempt, while an unknown identifier answers 401.
func TestAuditPoc_DisabledStatusOracle(t *testing.T) {
	ctx := context.Background()
	svc := identity.NewService(identitymemory.NewStore(), auditHasher(), auditPolicy())
	user, err := svc.Register(ctx, "", "gone@example.com", "SomeStrongPassword123!")
	require.NoError(t, err)
	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder())

	require.Equal(t, 429, auditLoginStatus(h.ServeHTTP, t, "gone@example.com", "SomeStrongPassword123!"),
		"VULNERABILITY DEMONSTRATED: disabled account answers 429")
	require.Equal(t, 401, auditLoginStatus(h.ServeHTTP, t, "never-existed@example.com", "SomeStrongPassword123!"),
		"unknown account answers 401 — existence is leaked by the status gap")
}
