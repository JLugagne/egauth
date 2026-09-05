package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/identity/storetest"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPolicy is a simple mock for passwords.Policy
type mockPolicy struct {
	VerifyFunc func(ctx context.Context, password string) error
}

func (m *mockPolicy) Verify(ctx context.Context, password string) error {
	if m.VerifyFunc == nil {
		panic("called not defined VerifyFunc")
	}
	return m.VerifyFunc(ctx, password)
}

func TestService_Register_NormalizesEmail(t *testing.T) {
	ctx := context.Background()
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{HashFunc: func(ctx context.Context, p string) (string, error) { return "h", nil }}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}
	svc := identity.NewService(store, hasher, policy)

	u1, err := svc.Register(ctx, "", "  User@Example.COM ", "pw")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", u1.Email, "email is trimmed and lowercased")

	// A case/space variant must resolve to the same account (no duplicate / pre-reg takeover).
	_, err = svc.Register(ctx, "", "user@example.com", "pw")
	assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)
}

func TestService_Register_RejectsInvalidEmail(t *testing.T) {
	ctx := context.Background()
	svc := identity.NewService(identitymemory.NewStore(), &hashertest.MockHasher{}, &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }})
	_, err := svc.Register(ctx, "", "not-an-email", "pw")
	assert.ErrorIs(t, err, identity.ErrInvalidEmail)
}

func TestService_RequestEmailVerification_EnumerationSafe(t *testing.T) {
	ctx := context.Background()
	store := &storetest.MockStore{
		CreateVerificationTokenFunc: func(ctx context.Context, tenantID string, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte) (string, error) {
			// The store's live/same-tenant guard reports a non-existent or foreign user as
			// ErrUserNotFound.
			return "", identity.ErrUserNotFound
		},
	}
	svc := identity.NewService(store, &hashertest.MockHasher{}, &mockPolicy{})

	token, err := svc.RequestEmailVerification(ctx, "", uuid.Must(uuid.NewV7()))
	// Must NOT surface a distinct error: a 500-vs-204 difference for a live/same-tenant account
	// is an account-enumeration oracle, unlike the other Request* flows.
	assert.NoError(t, err)
	assert.Empty(t, token)
}

func TestService_ChangePassword(t *testing.T) {
	ctx := context.Background()
	userID := uuid.Must(uuid.NewV7())
	const storedHash = "stored-hash"

	passwordIdent := func() []*identity.Identity {
		h := storedHash
		return []*identity.Identity{{ID: uuid.Must(uuid.NewV7()), UserID: userID, Provider: "password", PasswordHash: &h}}
	}

	t.Run("wrong current password is rejected and nothing is written", func(t *testing.T) {
		updated := false
		store := &storetest.MockStore{
			FindIdentitiesByUserIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) ([]*identity.Identity, error) {
				return passwordIdent(), nil
			},
			UpdateIdentityPasswordFunc: func(ctx context.Context, tenantID string, id uuid.UUID, hash string, changedAt time.Time, mustChange bool) error {
				updated = true
				return nil
			},
		}
		hasher := &hashertest.MockHasher{
			CompareFunc: func(ctx context.Context, hash, password string) error {
				assert.Equal(t, storedHash, hash)
				return passwords.ErrInvalidPassword
			},
			HashFunc: func(ctx context.Context, p string) (string, error) { return "new", nil },
		}
		policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}
		svc := identity.NewService(store, hasher, policy)

		err := svc.ChangePassword(ctx, "", userID, "wrong-current", "NewValidPass123!")
		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
		assert.False(t, updated, "password must not be updated when the current password is wrong")
	})

	t.Run("correct current and valid new updates the hash", func(t *testing.T) {
		var gotHash string
		store := &storetest.MockStore{
			FindIdentitiesByUserIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) ([]*identity.Identity, error) {
				assert.Equal(t, userID, id)
				return passwordIdent(), nil
			},
			UpdateIdentityPasswordFunc: func(ctx context.Context, tenantID string, id uuid.UUID, hash string, changedAt time.Time, mustChange bool) error {
				assert.Equal(t, userID, id)
				gotHash = hash
				return nil
			},
		}
		hasher := &hashertest.MockHasher{
			CompareFunc: func(ctx context.Context, hash, password string) error {
				assert.Equal(t, "current-pass", password)
				return nil
			},
			HashFunc: func(ctx context.Context, p string) (string, error) {
				assert.Equal(t, "NewValidPass123!", p)
				return "new-hash", nil
			},
		}
		policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}
		svc := identity.NewService(store, hasher, policy)

		err := svc.ChangePassword(ctx, "", userID, "current-pass", "NewValidPass123!")
		require.NoError(t, err)
		assert.Equal(t, "new-hash", gotHash)
	})

	t.Run("new password failing policy is rejected before the current is verified", func(t *testing.T) {
		compareCalled := false
		store := &storetest.MockStore{
			FindIdentitiesByUserIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) ([]*identity.Identity, error) {
				return passwordIdent(), nil
			},
		}
		hasher := &hashertest.MockHasher{
			CompareFunc: func(ctx context.Context, hash, password string) error { compareCalled = true; return nil },
		}
		policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return passwords.ErrPasswordTooShort }}
		svc := identity.NewService(store, hasher, policy)

		err := svc.ChangePassword(ctx, "", userID, "current", "weak")
		assert.ErrorIs(t, err, passwords.ErrPasswordTooShort)
		assert.False(t, compareCalled, "policy must be checked before verifying the current password")
	})

	t.Run("account without a password identity is rejected with a decoy hash", func(t *testing.T) {
		store := &storetest.MockStore{
			FindIdentitiesByUserIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) ([]*identity.Identity, error) {
				return []*identity.Identity{{Provider: "google", ProviderID: "x"}}, nil
			},
		}
		decoyed := false
		hasher := &hashertest.MockHasher{
			HashFunc: func(ctx context.Context, p string) (string, error) { decoyed = true; return "h", nil },
		}
		policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}
		svc := identity.NewService(store, hasher, policy)

		err := svc.ChangePassword(ctx, "", userID, "whatever", "NewValidPass123!")
		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
		assert.True(t, decoyed, "should apply a decoy hash to equalize timing for an account with no password")
	})

	t.Run("successful change runs account erasers", func(t *testing.T) {
		store := &storetest.MockStore{
			FindIdentitiesByUserIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) ([]*identity.Identity, error) {
				return passwordIdent(), nil
			},
			UpdateIdentityPasswordFunc: func(ctx context.Context, tenantID string, id uuid.UUID, hash string, changedAt time.Time, mustChange bool) error {
				return nil
			},
		}
		hasher := &hashertest.MockHasher{
			CompareFunc: func(ctx context.Context, hash, password string) error { return nil },
			HashFunc:    func(ctx context.Context, p string) (string, error) { return "h", nil },
		}
		policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}

		eraser1Run := false
		eraser2Run := false
		e1 := func(ctx context.Context, tenantID string, uid uuid.UUID) error {
			assert.Equal(t, userID, uid)
			eraser1Run = true
			return nil
		}
		e2 := func(ctx context.Context, tenantID string, uid uuid.UUID) error {
			assert.Equal(t, userID, uid)
			eraser2Run = true
			return nil
		}

		svc := identity.NewService(store, hasher, policy, identity.WithAccountErasers(e1, e2))

		err := svc.ChangePassword(ctx, "", userID, "current", "NewValidPass123!")
		require.NoError(t, err)
		assert.True(t, eraser1Run, "first eraser must run")
		assert.True(t, eraser2Run, "second eraser must run")
	})
}

func TestService_Register(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		email := "test@example.com"
		password := "ValidPassword123!"
		expectedHash := "hashed_password"
		expectedUser := &identity.User{
			ID:    uuid.Must(uuid.NewV7()),
			Email: email,
		}

		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, email string) (*identity.User, error) {
				return nil, identity.ErrUserNotFound
			},
			CreateUserFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				assert.Equal(t, email, e)
				return expectedUser, nil
			},
			AddIdentityFunc: func(ctx context.Context, tenantID string, ident *identity.Identity) error {
				assert.Equal(t, expectedUser.ID, ident.UserID)
				assert.Equal(t, "password", ident.Provider)
				assert.Equal(t, email, ident.ProviderID)
				assert.Equal(t, expectedHash, *ident.PasswordHash)
				return nil
			},
		}

		hasher := &hashertest.MockHasher{
			HashFunc: func(ctx context.Context, p string) (string, error) {
				assert.Equal(t, password, p)
				return expectedHash, nil
			},
		}

		policy := &mockPolicy{
			VerifyFunc: func(ctx context.Context, p string) error {
				assert.Equal(t, password, p)
				return nil
			},
		}

		svc := identity.NewService(store, hasher, policy)
		user, err := svc.Register(ctx, "", email, password)

		require.NoError(t, err)
		assert.Equal(t, expectedUser, user)
	})

	t.Run("policy failure", func(t *testing.T) {
		store := &storetest.MockStore{}
		hasher := &hashertest.MockHasher{}
		policy := &mockPolicy{
			VerifyFunc: func(ctx context.Context, p string) error {
				return passwords.ErrPasswordTooShort
			},
		}

		svc := identity.NewService(store, hasher, policy)
		user, err := svc.Register(ctx, "", "test@example.com", "short")

		assert.ErrorIs(t, err, passwords.ErrPasswordTooShort)
		assert.Nil(t, user)
	})

	t.Run("hash failure", func(t *testing.T) {
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, email string) (*identity.User, error) {
				return nil, identity.ErrUserNotFound
			},
		}
		hasher := &hashertest.MockHasher{
			HashFunc: func(ctx context.Context, p string) (string, error) {
				return "", passwords.ErrHashFailed
			},
		}
		policy := &mockPolicy{
			VerifyFunc: func(ctx context.Context, p string) error {
				return nil
			},
		}

		svc := identity.NewService(store, hasher, policy)
		user, err := svc.Register(ctx, "", "test@example.com", "password")

		assert.ErrorIs(t, err, passwords.ErrHashFailed)
		assert.Nil(t, user)
	})
}

func TestService_Authenticate(t *testing.T) {
	ctx := context.Background()

	t.Run("success password provider", func(t *testing.T) {
		email := "test@example.com"
		password := "password123"
		hash := "hashed"
		expectedUser := &identity.User{
			ID:    uuid.Must(uuid.NewV7()),
			Email: email,
		}

		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				assert.Equal(t, email, e)
				return expectedUser, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				assert.Equal(t, "password", p)
				assert.Equal(t, email, pid)
				return &identity.Identity{
					UserID:       expectedUser.ID,
					Provider:     "password",
					ProviderID:   email,
					PasswordHash: &hash,
				}, nil
			},
		}

		hasher := &hashertest.MockHasher{
			CompareFunc: func(ctx context.Context, h, p string) error {
				assert.Equal(t, hash, h)
				assert.Equal(t, password, p)
				return nil
			},
		}

		policy := &mockPolicy{}

		svc := identity.NewService(store, hasher, policy)
		user, err := svc.Authenticate(ctx, "", "password", email, password)

		require.NoError(t, err)
		assert.Equal(t, expectedUser, user)
	})

	t.Run("user not found", func(t *testing.T) {
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return nil, identity.ErrUserNotFound
			},
		}

		svc := identity.NewService(store, nil, nil)
		user, err := svc.Authenticate(ctx, "", "password", "test@example.com", "password")

		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
		assert.Nil(t, user)
	})

	t.Run("identity not found", func(t *testing.T) {
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				return nil, identity.ErrIdentityNotFound
			},
		}

		svc := identity.NewService(store, nil, nil)
		user, err := svc.Authenticate(ctx, "", "password", "test@example.com", "password")

		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
		assert.Nil(t, user)
	})

	t.Run("invalid password", func(t *testing.T) {
		hash := "hash"
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				return &identity.Identity{PasswordHash: &hash}, nil
			},
			IncrementFailedAttemptsFunc: func(ctx context.Context, tenantID string, id uuid.UUID, threshold int, dur time.Duration) (bool, error) {
				return false, nil
			},
		}

		hasher := &hashertest.MockHasher{
			CompareFunc: func(ctx context.Context, h, p string) error {
				return passwords.ErrInvalidPassword
			},
		}

		svc := identity.NewService(store, hasher, nil)
		user, err := svc.Authenticate(ctx, "", "password", "test@example.com", "wrong")

		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
		assert.Nil(t, user)
	})

	t.Run("non-password provider is rejected without resolving an identity", func(t *testing.T) {
		// Credential login must never authenticate an external (non-password) provider: doing so
		// would be a passwordless bypass (TASK-060). The store lookups must not even be reached.
		store := &storetest.MockStore{
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				t.Fatalf("FindIdentityByProvider must not be reached for a non-password provider")
				return nil, nil
			},
			FindUserByIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) (*identity.User, error) {
				t.Fatalf("FindUserByID must not be reached for a non-password provider")
				return nil, nil
			},
		}

		svc := identity.NewService(store, nil, nil)
		user, err := svc.Authenticate(ctx, "", "google", "sub123", "")

		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
		assert.Nil(t, user)
	})

	t.Run("create user fails", func(t *testing.T) {
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, email string) (*identity.User, error) {
				return nil, identity.ErrUserNotFound
			},
			CreateUserFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return nil, errors.New("db error")
			},
		}
		hasher := &hashertest.MockHasher{
			HashFunc: func(ctx context.Context, p string) (string, error) {
				return "hash", nil
			},
		}
		policy := &mockPolicy{
			VerifyFunc: func(ctx context.Context, p string) error { return nil },
		}

		svc := identity.NewService(store, hasher, policy)
		user, err := svc.Register(ctx, "", "test@example.com", "pass")

		assert.Error(t, err)
		assert.EqualError(t, err, "db error")
		assert.Nil(t, user)
	})

	t.Run("add identity fails", func(t *testing.T) {
		compensated := false
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, email string) (*identity.User, error) {
				return nil, identity.ErrUserNotFound
			},
			CreateUserFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
			},
			AddIdentityFunc: func(ctx context.Context, tenantID string, ident *identity.Identity) error {
				return errors.New("db error")
			},
			// Register must compensate the orphaned user when AddIdentity fails.
			DeleteUserFunc: func(ctx context.Context, tenantID string, id uuid.UUID) error {
				compensated = true
				return nil
			},
		}
		hasher := &hashertest.MockHasher{
			HashFunc: func(ctx context.Context, p string) (string, error) {
				return "hash", nil
			},
		}
		policy := &mockPolicy{
			VerifyFunc: func(ctx context.Context, p string) error { return nil },
		}

		svc := identity.NewService(store, hasher, policy)
		user, err := svc.Register(ctx, "", "test@example.com", "pass")

		assert.Error(t, err)
		assert.EqualError(t, err, "db error")
		assert.Nil(t, user)
		assert.True(t, compensated, "the orphaned user must be cleaned up")
	})

	t.Run("missing password hash", func(t *testing.T) {
		mockStore := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, email string) (*identity.User, error) {
				return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, provider, providerID string) (*identity.Identity, error) {
				return &identity.Identity{Provider: "password", PasswordHash: nil}, nil
			},
		}
		service := identity.NewService(mockStore, nil, nil)
		_, err := service.Authenticate(context.Background(), "", "password", "test@test.com", "pass")
		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
	})

	t.Run("non-password provider with a known identity is still rejected", func(t *testing.T) {
		// Even if the external identity and its user exist, the credential path must not
		// authenticate them: the password argument is never verifiable here (TASK-060).
		mockStore := &storetest.MockStore{
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, provider, providerID string) (*identity.Identity, error) {
				t.Fatalf("FindIdentityByProvider must not be reached for a non-password provider")
				return nil, nil
			},
			FindUserByIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) (*identity.User, error) {
				t.Fatalf("FindUserByID must not be reached for a non-password provider")
				return nil, nil
			},
		}
		service := identity.NewService(mockStore, nil, nil)
		user, err := service.Authenticate(context.Background(), "", "google", "12345", "")
		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
		assert.Nil(t, user)
	})
}

// TestService_Authenticate_NonPasswordProviderRejected pins the fix for the auth-bypass
// finding (TASK-060): the credential (form) login path must NOT authenticate a non-password
// provider. Previously, Authenticate looked up the identity by (provider, providerID), loaded
// the user, and returned it WITHOUT ever comparing the supplied password — so a consumer that
// set WithProvider("google") turned the login form into a passwordless bypass: any known
// external sub plus any/empty password yielded a valid user and a token pair. After the fix
// the path must reject any provider != "password" with ErrInvalidCredentials and never resolve
// a user.
func TestService_Authenticate_NonPasswordProviderRejected(t *testing.T) {
	ctx := context.Background()
	knownOAuthSub := "known-google-sub-123"

	// The store would happily resolve the external identity and user; the guard must run
	// before any of these are reached so a known sub cannot be turned into a session.
	store := &storetest.MockStore{
		FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
			t.Fatalf("FindIdentityByProvider must not be reached for a non-password provider (provider=%q id=%q)", p, pid)
			return nil, nil
		},
		FindUserByIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) (*identity.User, error) {
			t.Fatalf("FindUserByID must not be reached for a non-password provider")
			return nil, nil
		},
	}

	// A hasher is wired so the decoy-hash timing-equalization path is exercised on rejection.
	hasher := &hashertest.MockHasher{
		HashFunc: func(ctx context.Context, p string) (string, error) {
			return "decoy", nil
		},
	}

	svc := identity.NewService(store, hasher, nil)

	user, err := svc.Authenticate(ctx, "tenant", "google", knownOAuthSub, "anypassword")

	assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
	assert.Nil(t, user, "a non-password provider must never resolve a user via the credential login path")
}

func TestService_Authenticate_ConstantTime(t *testing.T) {
	ctx := context.Background()

	// These tests pin the STRUCTURAL half of the PRD requirement (§108): the password
	// authentication path must apply an equivalent hashing cost even when no real password
	// hash is available, so an attacker cannot distinguish "user does not exist" from
	// "wrong password". They assert the decoy hash is *invoked* on each enumeration-safe
	// path — they do NOT (and cannot) prove timing uniformity, since a passing boolean
	// assertion says nothing about the wall-clock delta. The timing *evidence* lives in the
	// BenchmarkAuthenticate_* benchmarks (authenticate_bench_test.go): run them with
	//   go test -run=^$ -bench=BenchmarkAuthenticate -benchmem -count=10 ./identity
	// and compare the valid-user vs unknown-user variants with benchstat (see SECURITY.md).

	t.Run("user not found still performs a hashing cost", func(t *testing.T) {
		var hashed bool
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return nil, identity.ErrUserNotFound
			},
		}
		hasher := &hashertest.MockHasher{
			HashFunc: func(ctx context.Context, p string) (string, error) { hashed = true; return "decoy", nil },
		}
		svc := identity.NewService(store, hasher, nil)
		_, err := svc.Authenticate(ctx, "", "password", "ghost@example.com", "pw")
		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
		assert.True(t, hashed, "must apply a hashing cost when the user does not exist")
	})

	t.Run("identity not found still performs a hashing cost", func(t *testing.T) {
		var hashed bool
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				return nil, identity.ErrIdentityNotFound
			},
		}
		hasher := &hashertest.MockHasher{
			HashFunc: func(ctx context.Context, p string) (string, error) { hashed = true; return "decoy", nil },
		}
		svc := identity.NewService(store, hasher, nil)
		_, err := svc.Authenticate(ctx, "", "password", "test@example.com", "pw")
		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
		assert.True(t, hashed, "must apply a hashing cost when the identity does not exist")
	})

	t.Run("missing password hash still performs a hashing cost", func(t *testing.T) {
		var hashed bool
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				return &identity.Identity{Provider: "password", PasswordHash: nil}, nil
			},
		}
		hasher := &hashertest.MockHasher{
			HashFunc: func(ctx context.Context, p string) (string, error) { hashed = true; return "decoy", nil },
		}
		svc := identity.NewService(store, hasher, nil)
		_, err := svc.Authenticate(ctx, "", "password", "test@example.com", "pw")
		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
		assert.True(t, hashed, "must apply a hashing cost when the identity has no password hash")
	})
}

// TestService_Authenticate_TimingEqualization confirms that the locked and
// administratively-disabled rejection paths spend an equivalent hashing cost
// (decoyHash) before returning, exactly like the unknown-user / no-password
// paths. Without it, a known-locked or known-disabled account answers measurably
// faster than an unknown one, reopening a user-enumeration timing oracle
// (distinguishing "exists but locked/disabled" from "does not exist").
func TestService_Authenticate_TimingEqualization(t *testing.T) {
	ctx := context.Background()
	email := "timing@example.com"
	hash := "hashed"

	t.Run("locked account applies a decoy hash before rejecting", func(t *testing.T) {
		future := time.Now().Add(10 * time.Minute)
		ident := &identity.Identity{ID: uuid.Must(uuid.NewV7()), Provider: "password", ProviderID: email, PasswordHash: &hash, LockedUntil: &future}
		var hashed, compared bool
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				return ident, nil
			},
		}
		hasher := &hashertest.MockHasher{
			HashFunc:    func(ctx context.Context, p string) (string, error) { hashed = true; return "decoy", nil },
			CompareFunc: func(ctx context.Context, h, p string) error { compared = true; return nil },
		}
		svc := identity.NewService(store, hasher, nil)
		_, err := svc.Authenticate(ctx, "", "password", email, "irrelevant")
		assert.ErrorIs(t, err, identity.ErrAccountLocked)
		assert.False(t, compared, "must not compare the password for a locked account")
		assert.True(t, hashed, "locked path must apply a decoy hash to equalize timing with the unknown-user path")
	})

	t.Run("disabled account applies a decoy hash before rejecting", func(t *testing.T) {
		disabledAt := time.Now().Add(-time.Hour)
		ident := &identity.Identity{ID: uuid.Must(uuid.NewV7()), Provider: "password", ProviderID: email, PasswordHash: &hash}
		var hashed, compared bool
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{ID: uuid.Must(uuid.NewV7()), DisabledAt: &disabledAt}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				return ident, nil
			},
		}
		hasher := &hashertest.MockHasher{
			HashFunc:    func(ctx context.Context, p string) (string, error) { hashed = true; return "decoy", nil },
			CompareFunc: func(ctx context.Context, h, p string) error { compared = true; return nil },
		}
		svc := identity.NewService(store, hasher, nil)
		_, err := svc.Authenticate(ctx, "", "password", email, "irrelevant")
		assert.ErrorIs(t, err, identity.ErrAccountDisabled)
		assert.False(t, compared, "must not compare the password for a disabled account")
		assert.True(t, hashed, "disabled path must apply a decoy hash to equalize timing with the unknown-user path")
	})
}

func TestService_Lockout(t *testing.T) {
	ctx := context.Background()
	email := "lock@example.com"
	hash := "hashed"

	t.Run("password mismatch increments failed attempts", func(t *testing.T) {
		ident := &identity.Identity{ID: uuid.Must(uuid.NewV7()), Provider: "password", ProviderID: email, PasswordHash: &hash}
		var incremented bool
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				return ident, nil
			},
			IncrementFailedAttemptsFunc: func(ctx context.Context, tenantID string, id uuid.UUID, threshold int, dur time.Duration) (bool, error) {
				assert.Equal(t, ident.ID, id)
				incremented = true
				return false, nil
			},
		}
		hasher := &hashertest.MockHasher{
			CompareFunc: func(ctx context.Context, h, p string) error { return passwords.ErrInvalidPassword },
		}
		svc := identity.NewService(store, hasher, nil)
		_, err := svc.Authenticate(ctx, "", "password", email, "wrong")
		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
		assert.True(t, incremented, "failed attempt must be recorded")
	})

	t.Run("locked account returns ErrAccountLocked without comparing password", func(t *testing.T) {
		future := time.Now().Add(10 * time.Minute)
		ident := &identity.Identity{ID: uuid.Must(uuid.NewV7()), Provider: "password", ProviderID: email, PasswordHash: &hash, LockedUntil: &future}
		var compared bool
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				return ident, nil
			},
		}
		hasher := &hashertest.MockHasher{
			HashFunc:    func(ctx context.Context, p string) (string, error) { return "decoy", nil },
			CompareFunc: func(ctx context.Context, h, p string) error { compared = true; return nil },
		}
		svc := identity.NewService(store, hasher, nil)
		_, err := svc.Authenticate(ctx, "", "password", email, "irrelevant")
		assert.ErrorIs(t, err, identity.ErrAccountLocked)
		assert.False(t, compared, "must not compare password for locked account")
	})

	t.Run("expired lock allows authentication and resets", func(t *testing.T) {
		past := time.Now().Add(-10 * time.Minute)
		uid := uuid.Must(uuid.NewV7())
		ident := &identity.Identity{ID: uuid.Must(uuid.NewV7()), Provider: "password", ProviderID: email, PasswordHash: &hash, LockedUntil: &past, FailedAttempts: 5}
		var reset bool
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{ID: uid}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				return ident, nil
			},
			ResetFailedAttemptsFunc: func(ctx context.Context, tenantID string, id uuid.UUID) error {
				reset = true
				return nil
			},
		}
		hasher := &hashertest.MockHasher{
			CompareFunc: func(ctx context.Context, h, p string) error { return nil },
		}
		svc := identity.NewService(store, hasher, nil)
		user, err := svc.Authenticate(ctx, "", "password", email, "correct")
		require.NoError(t, err)
		assert.Equal(t, uid, user.ID)
		assert.True(t, reset, "successful auth after prior failures must reset counter")
	})

	t.Run("successful auth resets counter when attempts exist", func(t *testing.T) {
		uid := uuid.Must(uuid.NewV7())
		ident := &identity.Identity{ID: uuid.Must(uuid.NewV7()), Provider: "password", ProviderID: email, PasswordHash: &hash, FailedAttempts: 2}
		var reset bool
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{ID: uid}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				return ident, nil
			},
			ResetFailedAttemptsFunc: func(ctx context.Context, tenantID string, id uuid.UUID) error {
				reset = true
				return nil
			},
		}
		hasher := &hashertest.MockHasher{
			CompareFunc: func(ctx context.Context, h, p string) error { return nil },
		}
		svc := identity.NewService(store, hasher, nil)
		_, err := svc.Authenticate(ctx, "", "password", email, "correct")
		require.NoError(t, err)
		assert.True(t, reset)
	})

	t.Run("successful auth with no prior attempts does not reset", func(t *testing.T) {
		uid := uuid.Must(uuid.NewV7())
		ident := &identity.Identity{ID: uuid.Must(uuid.NewV7()), Provider: "password", ProviderID: email, PasswordHash: &hash, FailedAttempts: 0}
		store := &storetest.MockStore{
			FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
				return &identity.User{ID: uid}, nil
			},
			FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
				return ident, nil
			},
			// ResetFailedAttemptsFunc intentionally nil: it must NOT be called.
		}
		hasher := &hashertest.MockHasher{
			CompareFunc: func(ctx context.Context, h, p string) error { return nil },
		}
		svc := identity.NewService(store, hasher, nil)
		_, err := svc.Authenticate(ctx, "", "password", email, "correct")
		require.NoError(t, err)
	})
}

func TestResetPassword_PreAuthArgon2id(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid token does not invoke hasher", func(t *testing.T) {
		hashCalled := false
		hasher := &hashertest.MockHasher{
			HashFunc: func(ctx context.Context, password string) (string, error) {
				hashCalled = true
				return "hash", nil
			},
		}
		policy := &mockPolicy{
			VerifyFunc: func(ctx context.Context, password string) error {
				return nil
			},
		}
		store := &storetest.MockStore{
			ConsumeVerificationTokenFunc: func(ctx context.Context, tenantID string, token, kind string) (uuid.UUID, []byte, error) {
				return uuid.Nil, nil, identity.ErrVerificationTokenNotFound
			},
		}
		svc := identity.NewService(store, hasher, policy)

		err := svc.ResetPassword(ctx, "", "invalid-token", "ValidPassword123!")
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
		assert.False(t, hashCalled, "hasher.Hash must not be called when reset token is invalid")
	})

	t.Run("expired token does not invoke hasher", func(t *testing.T) {
		hashCalled := false
		hasher := &hashertest.MockHasher{
			HashFunc: func(ctx context.Context, password string) (string, error) {
				hashCalled = true
				return "hash", nil
			},
		}
		policy := &mockPolicy{
			VerifyFunc: func(ctx context.Context, password string) error {
				return nil
			},
		}
		store := &storetest.MockStore{
			ConsumeVerificationTokenFunc: func(ctx context.Context, tenantID string, token, kind string) (uuid.UUID, []byte, error) {
				return uuid.Nil, nil, identity.ErrVerificationTokenExpired
			},
		}
		svc := identity.NewService(store, hasher, policy)

		err := svc.ResetPassword(ctx, "", "expired-token", "ValidPassword123!")
		assert.ErrorIs(t, err, identity.ErrVerificationTokenExpired)
		assert.False(t, hashCalled, "hasher.Hash must not be called when reset token is expired")
	})
}

func TestRegister_DuplicateEmail_NoHashing(t *testing.T) {
	ctx := context.Background()
	const email = "existing@example.com"

	hashCalled := false
	hasher := &hashertest.MockHasher{
		HashFunc: func(ctx context.Context, password string) (string, error) {
			hashCalled = true
			return "hash", nil
		},
	}
	policy := &mockPolicy{
		VerifyFunc: func(ctx context.Context, password string) error {
			return nil
		},
	}
	store := &storetest.MockStore{
		FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
			if e == email {
				return &identity.User{ID: uuid.Must(uuid.NewV7()), Email: email}, nil
			}
			return nil, identity.ErrUserNotFound
		},
		CreateUserFunc: func(ctx context.Context, tenantID string, email string) (*identity.User, error) {
			return nil, identity.ErrEmailAlreadyExists
		},
	}
	svc := identity.NewService(store, hasher, policy)

	_, err := svc.Register(ctx, "", email, "ValidPassword123!")
	assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)
	assert.False(t, hashCalled, "hasher.Hash must not be called when registering an existing email")
}
