package storetest

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/sessions"
	"github.com/google/uuid"
)

// MockStore is a functional mock of the sessions.Store interface.
type MockStore struct {
	CreateSessionFunc          func(ctx context.Context, tenantID string, session *sessions.Session) error
	FindSessionByHashFunc      func(ctx context.Context, tenantID string, tokenHash string) (*sessions.Session, error)
	UpdateSessionFunc          func(ctx context.Context, tenantID string, session *sessions.Session, expectedTokenHash string) error
	BindSessionFunc            func(ctx context.Context, tenantID string, session *sessions.Session, expectedTokenHash string) error
	DeleteSessionFunc          func(ctx context.Context, tenantID string, id uuid.UUID) error
	DeleteSessionsByUserIDFunc func(ctx context.Context, tenantID string, userID uuid.UUID) error
	DeleteExpiredFunc          func(ctx context.Context, tenantID string) (int64, error)
}

func (m *MockStore) CreateSession(ctx context.Context, tenantID string, session *sessions.Session) error {
	if m.CreateSessionFunc == nil {
		panic("called not defined CreateSessionFunc")
	}
	return m.CreateSessionFunc(ctx, tenantID, session)
}

func (m *MockStore) FindSessionByHash(ctx context.Context, tenantID string, tokenHash string) (*sessions.Session, error) {
	if m.FindSessionByHashFunc == nil {
		panic("called not defined FindSessionByHashFunc")
	}
	return m.FindSessionByHashFunc(ctx, tenantID, tokenHash)
}

func (m *MockStore) UpdateSession(ctx context.Context, tenantID string, session *sessions.Session, expectedTokenHash string) error {
	if m.UpdateSessionFunc == nil {
		panic("called not defined UpdateSessionFunc")
	}
	return m.UpdateSessionFunc(ctx, tenantID, session, expectedTokenHash)
}

func (m *MockStore) BindSession(ctx context.Context, tenantID string, session *sessions.Session, expectedTokenHash string) error {
	if m.BindSessionFunc == nil {
		panic("called not defined BindSessionFunc")
	}
	return m.BindSessionFunc(ctx, tenantID, session, expectedTokenHash)
}

func (m *MockStore) DeleteSession(ctx context.Context, tenantID string, id uuid.UUID) error {
	if m.DeleteSessionFunc == nil {
		panic("called not defined DeleteSessionFunc")
	}
	return m.DeleteSessionFunc(ctx, tenantID, id)
}

func (m *MockStore) DeleteSessionsByUserID(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if m.DeleteSessionsByUserIDFunc == nil {
		panic("called not defined DeleteSessionsByUserIDFunc")
	}
	return m.DeleteSessionsByUserIDFunc(ctx, tenantID, userID)
}

func (m *MockStore) DeleteExpired(ctx context.Context, tenantID string) (int64, error) {
	if m.DeleteExpiredFunc == nil {
		panic("called not defined DeleteExpiredFunc")
	}
	return m.DeleteExpiredFunc(ctx, tenantID)
}

// StoreContractTesting runs the full sessions.Store contract suite against any implementation.
// It composes the segmented capability suites: SessionStoreContract (the stable-core
// create/lookup/mutate/delete plus the compare-and-set concurrency contract) and
// SessionReaperContract (the optional DeleteExpired sweep). An implementer that provides only one
// capability can call the matching per-capability function directly.
func StoreContractTesting(t *testing.T, store sessions.Store, useMultiTenant bool) {
	SessionStoreContract(t, store, useMultiTenant)
	SessionReaperContract(t, store, useMultiTenant)
}
