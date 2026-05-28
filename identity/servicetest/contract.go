package servicetest

import (
	"context"

	"github.com/JLugagne/libauth/identity"
)

// MockService is a mock implementation of the identity.Service interface.
type MockService struct {
	RegisterFunc     func(ctx context.Context, email, password string, opts ...identity.Option) (*identity.User, error)
	AuthenticateFunc func(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error)
}

var _ identity.Service = (*MockService)(nil)

func (m *MockService) Register(ctx context.Context, email, password string, opts ...identity.Option) (*identity.User, error) {
	if m.RegisterFunc == nil {
		panic("called not defined RegisterFunc")
	}
	return m.RegisterFunc(ctx, email, password, opts...)
}

func (m *MockService) Authenticate(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error) {
	if m.AuthenticateFunc == nil {
		panic("called not defined AuthenticateFunc")
	}
	return m.AuthenticateFunc(ctx, provider, providerID, password, opts...)
}
