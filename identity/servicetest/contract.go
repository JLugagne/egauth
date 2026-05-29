package servicetest

import (
	"context"

	"github.com/JLugagne/libauth/identity"
	"github.com/google/uuid"
)

// MockService is a mock implementation of the identity.Service interface.
type MockService struct {
	RegisterFunc     func(ctx context.Context, email, password string, opts ...identity.Option) (*identity.User, error)
	AuthenticateFunc func(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error)

	RequestPasswordResetFunc     func(ctx context.Context, email string, opts ...identity.Option) (string, *identity.User, error)
	ResetPasswordFunc            func(ctx context.Context, token, newPassword string, opts ...identity.Option) error
	RequestEmailVerificationFunc func(ctx context.Context, userID uuid.UUID, opts ...identity.Option) (string, error)
	VerifyEmailFunc              func(ctx context.Context, token string, opts ...identity.Option) (*identity.User, error)
	LinkOrCreateIdentityFunc     func(ctx context.Context, provider, providerID, email string, emailVerified bool, opts ...identity.Option) (*identity.User, error)
	RequestMagicLinkFunc         func(ctx context.Context, email string, opts ...identity.Option) (string, *identity.User, error)
	LoginWithMagicLinkFunc       func(ctx context.Context, token string, opts ...identity.Option) (*identity.User, error)
	ChangePasswordFunc           func(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string, opts ...identity.Option) error
	RequestEmailChangeFunc       func(ctx context.Context, userID uuid.UUID, newEmail string, opts ...identity.Option) (string, error)
	ConfirmEmailChangeFunc       func(ctx context.Context, token string, opts ...identity.Option) (*identity.User, error)
	DeleteAccountFunc            func(ctx context.Context, userID uuid.UUID, opts ...identity.Option) error
}

func (m *MockService) DeleteAccount(ctx context.Context, userID uuid.UUID, opts ...identity.Option) error {
	if m.DeleteAccountFunc == nil {
		panic("called not defined DeleteAccountFunc")
	}
	return m.DeleteAccountFunc(ctx, userID, opts...)
}

func (m *MockService) RequestEmailChange(ctx context.Context, userID uuid.UUID, newEmail string, opts ...identity.Option) (string, error) {
	if m.RequestEmailChangeFunc == nil {
		panic("called not defined RequestEmailChangeFunc")
	}
	return m.RequestEmailChangeFunc(ctx, userID, newEmail, opts...)
}

func (m *MockService) ConfirmEmailChange(ctx context.Context, token string, opts ...identity.Option) (*identity.User, error) {
	if m.ConfirmEmailChangeFunc == nil {
		panic("called not defined ConfirmEmailChangeFunc")
	}
	return m.ConfirmEmailChangeFunc(ctx, token, opts...)
}

func (m *MockService) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string, opts ...identity.Option) error {
	if m.ChangePasswordFunc == nil {
		panic("called not defined ChangePasswordFunc")
	}
	return m.ChangePasswordFunc(ctx, userID, currentPassword, newPassword, opts...)
}

func (m *MockService) RequestMagicLink(ctx context.Context, email string, opts ...identity.Option) (string, *identity.User, error) {
	if m.RequestMagicLinkFunc == nil {
		panic("called not defined RequestMagicLinkFunc")
	}
	return m.RequestMagicLinkFunc(ctx, email, opts...)
}

func (m *MockService) LoginWithMagicLink(ctx context.Context, token string, opts ...identity.Option) (*identity.User, error) {
	if m.LoginWithMagicLinkFunc == nil {
		panic("called not defined LoginWithMagicLinkFunc")
	}
	return m.LoginWithMagicLinkFunc(ctx, token, opts...)
}

var _ identity.Service = (*MockService)(nil)

func (m *MockService) RequestPasswordReset(ctx context.Context, email string, opts ...identity.Option) (string, *identity.User, error) {
	if m.RequestPasswordResetFunc == nil {
		panic("called not defined RequestPasswordResetFunc")
	}
	return m.RequestPasswordResetFunc(ctx, email, opts...)
}

func (m *MockService) ResetPassword(ctx context.Context, token, newPassword string, opts ...identity.Option) error {
	if m.ResetPasswordFunc == nil {
		panic("called not defined ResetPasswordFunc")
	}
	return m.ResetPasswordFunc(ctx, token, newPassword, opts...)
}

func (m *MockService) RequestEmailVerification(ctx context.Context, userID uuid.UUID, opts ...identity.Option) (string, error) {
	if m.RequestEmailVerificationFunc == nil {
		panic("called not defined RequestEmailVerificationFunc")
	}
	return m.RequestEmailVerificationFunc(ctx, userID, opts...)
}

func (m *MockService) VerifyEmail(ctx context.Context, token string, opts ...identity.Option) (*identity.User, error) {
	if m.VerifyEmailFunc == nil {
		panic("called not defined VerifyEmailFunc")
	}
	return m.VerifyEmailFunc(ctx, token, opts...)
}

func (m *MockService) LinkOrCreateIdentity(ctx context.Context, provider, providerID, email string, emailVerified bool, opts ...identity.Option) (*identity.User, error) {
	if m.LinkOrCreateIdentityFunc == nil {
		panic("called not defined LinkOrCreateIdentityFunc")
	}
	return m.LinkOrCreateIdentityFunc(ctx, provider, providerID, email, emailVerified, opts...)
}

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
