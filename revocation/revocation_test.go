package revocation_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/revocation"
)

// mockHandler records received revocations.
type mockHandler struct {
	mu      sync.Mutex
	calls   []revocation.Revocation
	err     error
	waitFor chan struct{} // optional: block until signaled
}

func (m *mockHandler) HandleRevocation(ctx context.Context, rev revocation.Revocation) error {
	if m.waitFor != nil {
		select {
		case <-m.waitFor:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, rev)
	return m.err
}

func (m *mockHandler) received() []revocation.Revocation {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]revocation.Revocation{}, m.calls...)
}

func TestMemBus_Publish_DispatchesToSubscribers(t *testing.T) {
	bus := revocation.NewMemBus()
	h1 := &mockHandler{}
	h2 := &mockHandler{}

	bus.Subscribe(revocation.TargetUser, h1)
	bus.Subscribe(revocation.TargetUser, h2)

	rev := revocation.Revocation{
		TenantID:   "tenant-1",
		TargetType: revocation.TargetUser,
		TargetID:   uuid.New().String(),
		Scope:      revocation.ScopeAll,
		Reason:     revocation.ReasonPasswordChanged,
		CutoffTime: time.Now(),
	}

	err := bus.Publish(context.Background(), rev)
	require.NoError(t, err)

	assert.Len(t, h1.received(), 1)
	assert.Len(t, h2.received(), 1)
	assert.Equal(t, rev.TargetID, h1.received()[0].TargetID)
	assert.Equal(t, rev.TargetID, h2.received()[0].TargetID)
}

func TestMemBus_Publish_OnlyMatchingTargetTypeReceives(t *testing.T) {
	bus := revocation.NewMemBus()
	userHandler := &mockHandler{}
	tenantHandler := &mockHandler{}

	bus.Subscribe(revocation.TargetUser, userHandler)
	bus.Subscribe(revocation.TargetTenant, tenantHandler)

	rev := revocation.Revocation{
		TenantID:   "tenant-1",
		TargetType: revocation.TargetUser,
		TargetID:   uuid.New().String(),
		Scope:      revocation.ScopeAll,
		Reason:     revocation.ReasonAccountDisabled,
	}

	err := bus.Publish(context.Background(), rev)
	require.NoError(t, err)

	assert.Len(t, userHandler.received(), 1)
	assert.Empty(t, tenantHandler.received(), "tenant handler must not receive user revocations")
}

func TestMemBus_Publish_WildcardSubscriberReceivesAll(t *testing.T) {
	bus := revocation.NewMemBus()
	wildcard := &mockHandler{}
	specific := &mockHandler{}

	bus.Subscribe(revocation.TargetAll, wildcard) // wildcard
	bus.Subscribe(revocation.TargetUser, specific)

	rev := revocation.Revocation{
		TenantID:   "tenant-1",
		TargetType: revocation.TargetUser,
		TargetID:   uuid.New().String(),
		Scope:      revocation.ScopeAll,
		Reason:     revocation.ReasonLogoutEverywhere,
	}

	err := bus.Publish(context.Background(), rev)
	require.NoError(t, err)

	assert.Len(t, wildcard.received(), 1, "wildcard subscriber must receive every event")
	assert.Len(t, specific.received(), 1)
}

func TestMemBus_Publish_AggregatesHandlerErrors(t *testing.T) {
	bus := revocation.NewMemBus()
	errA := errors.New("handler A failed")
	errB := errors.New("handler B failed")

	bus.Subscribe(revocation.TargetUser, &mockHandler{err: errA})
	bus.Subscribe(revocation.TargetUser, &mockHandler{err: errB})

	rev := revocation.Revocation{
		TargetType: revocation.TargetUser,
		TargetID:   uuid.New().String(),
	}

	err := bus.Publish(context.Background(), rev)
	require.Error(t, err)
	assert.ErrorIs(t, err, errA)
	assert.ErrorIs(t, err, errB)
}

func TestMemBus_Publish_NoSubscribers_NoError(t *testing.T) {
	bus := revocation.NewMemBus()
	rev := revocation.Revocation{
		TargetType: revocation.TargetUser,
		TargetID:   uuid.New().String(),
	}

	err := bus.Publish(context.Background(), rev)
	assert.NoError(t, err)
}

func TestMemBus_Publish_CancelledContext_ReturnsContextError(t *testing.T) {
	bus := revocation.NewMemBus()
	blocker := &mockHandler{waitFor: make(chan struct{})}
	bus.Subscribe(revocation.TargetUser, blocker)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	rev := revocation.Revocation{
		TargetType: revocation.TargetUser,
		TargetID:   uuid.New().String(),
	}

	err := bus.Publish(ctx, rev)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestRevocation_Constants(t *testing.T) {
	// Verify enum values are stable — downstream code may serialize them.
	assert.Equal(t, revocation.TargetType("user"), revocation.TargetUser)
	assert.Equal(t, revocation.TargetType("tenant"), revocation.TargetTenant)
	assert.Equal(t, revocation.TargetType("session"), revocation.TargetSession)
	assert.Equal(t, revocation.TargetType("token_family"), revocation.TargetTokenFamily)
	assert.Equal(t, revocation.TargetType("*"), revocation.TargetAll)

	assert.Equal(t, revocation.Scope("all"), revocation.ScopeAll)
	assert.Equal(t, revocation.Scope("interactive"), revocation.ScopeInteractive)
	assert.Equal(t, revocation.Scope("sessions"), revocation.ScopeSessionsOnly)
	assert.Equal(t, revocation.Scope("tokens"), revocation.ScopeTokensOnly)

	assert.Equal(t, revocation.Reason("password_changed"), revocation.ReasonPasswordChanged)
	assert.Equal(t, revocation.Reason("password_reset"), revocation.ReasonPasswordReset)
	assert.Equal(t, revocation.Reason("account_disabled"), revocation.ReasonAccountDisabled)
	assert.Equal(t, revocation.Reason("account_deleted"), revocation.ReasonAccountDeleted)
	assert.Equal(t, revocation.Reason("token_reuse_detected"), revocation.ReasonTokenReuseDetected)
	assert.Equal(t, revocation.Reason("logout_everywhere"), revocation.ReasonLogoutEverywhere)
	assert.Equal(t, revocation.Reason("tenant_deactivated"), revocation.ReasonTenantDeactivated)
	assert.Equal(t, revocation.Reason("tenant_deleted"), revocation.ReasonTenantDeleted)
}

func TestNewAccountRevocationHook_PublishesUserRevocation(t *testing.T) {
	bus := revocation.NewMemBus()
	h := &mockHandler{}
	bus.Subscribe(revocation.TargetUser, h)

	hook := revocation.NewAccountRevocationHook(bus, revocation.ReasonPasswordChanged, revocation.ScopeInteractive)

	userID := uuid.New()
	err := hook(context.Background(), "tenant-1", userID)
	require.NoError(t, err)

	received := h.received()
	require.Len(t, received, 1)
	assert.Equal(t, revocation.TargetUser, received[0].TargetType)
	assert.Equal(t, userID.String(), received[0].TargetID)
	assert.Equal(t, "tenant-1", received[0].TenantID)
	assert.Equal(t, revocation.ReasonPasswordChanged, received[0].Reason)
	assert.Equal(t, revocation.ScopeInteractive, received[0].Scope)
	assert.False(t, received[0].CutoffTime.IsZero(), "CutoffTime must be set")
}

func TestNewTenantRevocationHook_PublishesTenantRevocation(t *testing.T) {
	bus := revocation.NewMemBus()
	h := &mockHandler{}
	bus.Subscribe(revocation.TargetTenant, h)

	hook := revocation.NewTenantRevocationHook(bus, revocation.ReasonTenantDeleted)

	err := hook(context.Background(), "tenant-dead")
	require.NoError(t, err)

	received := h.received()
	require.Len(t, received, 1)
	assert.Equal(t, revocation.TargetTenant, received[0].TargetType)
	assert.Equal(t, "tenant-dead", received[0].TargetID)
	assert.Equal(t, "tenant-dead", received[0].TenantID)
	assert.Equal(t, revocation.ReasonTenantDeleted, received[0].Reason)
	assert.Equal(t, revocation.ScopeAll, received[0].Scope)
}
