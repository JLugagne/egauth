package servicetest

import (
	"context"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/google/uuid"
)

// MockService is a mock implementation of the identity.Service interface.
type MockService struct {
	RegisterFunc                        func(ctx context.Context, tenantID string, email, password string) (*identity.User, error)
	AuthenticateFunc                    func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error)
	RequestPasswordResetFunc            func(ctx context.Context, tenantID string, email string) (string, *identity.User, error)
	ResetPasswordFunc                   func(ctx context.Context, tenantID string, token, newPassword string) error
	RequestEmailVerificationFunc        func(ctx context.Context, tenantID string, userID uuid.UUID) (string, error)
	VerifyEmailFunc                     func(ctx context.Context, tenantID string, token string) (*identity.User, error)
	LinkOrCreateIdentityFunc            func(ctx context.Context, tenantID string, provider, providerID, email string, emailVerified bool) (*identity.User, error)
	RequestMagicLinkFunc                func(ctx context.Context, tenantID string, email string) (string, *identity.User, error)
	LoginWithMagicLinkFunc              func(ctx context.Context, tenantID string, token string, rc ...event.RequestContext) (*identity.User, error)
	ChangePasswordFunc                  func(ctx context.Context, tenantID string, userID uuid.UUID, currentPassword, newPassword string) error
	RequestEmailChangeFunc              func(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string) (string, error)
	ConfirmEmailChangeFunc              func(ctx context.Context, tenantID string, token string) (*identity.User, error)
	RequestPhoneVerificationFunc        func(ctx context.Context, tenantID string, userID uuid.UUID, phone string) (string, error)
	ConfirmPhoneVerificationFunc        func(ctx context.Context, tenantID string, token string) (*identity.User, error)
	RequestRecoveryEmailFunc            func(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string) (string, error)
	ConfirmRecoveryEmailFunc            func(ctx context.Context, tenantID string, token string) (*identity.User, error)
	RecoveryChannelsFunc                func(ctx context.Context, tenantID string, userID uuid.UUID) (identity.RecoveryChannels, error)
	RequestPasswordResetViaRecoveryFunc func(ctx context.Context, tenantID string, email string) (string, *identity.User, identity.RecoveryChannels, error)
	DeleteAccountFunc                   func(ctx context.Context, tenantID string, userID uuid.UUID) error
	DisableUserFunc                     func(ctx context.Context, tenantID string, userID uuid.UUID) error
	EnableUserFunc                      func(ctx context.Context, tenantID string, userID uuid.UUID) error
	PasswordChangeRequiredFunc          func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error)
	SetTemporaryPasswordFunc            func(ctx context.Context, tenantID string, userID uuid.UUID, tempPassword string) error
	AdminCreateUserFunc                 func(ctx context.Context, tenantID string, email, tempPassword string) (*identity.User, error)
}

func (m *MockService) DeleteAccount(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if m.DeleteAccountFunc == nil {
		panic("called not defined DeleteAccountFunc")
	}
	return m.DeleteAccountFunc(ctx, tenantID, userID)
}

func (m *MockService) RequestEmailChange(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string) (string, error) {
	if m.RequestEmailChangeFunc == nil {
		panic("called not defined RequestEmailChangeFunc")
	}
	return m.RequestEmailChangeFunc(ctx, tenantID, userID, newEmail)
}

func (m *MockService) ConfirmEmailChange(ctx context.Context, tenantID string, token string) (*identity.User, error) {
	if m.ConfirmEmailChangeFunc == nil {
		panic("called not defined ConfirmEmailChangeFunc")
	}
	return m.ConfirmEmailChangeFunc(ctx, tenantID, token)
}

func (m *MockService) ChangePassword(ctx context.Context, tenantID string, userID uuid.UUID, currentPassword, newPassword string) error {
	if m.ChangePasswordFunc == nil {
		panic("called not defined ChangePasswordFunc")
	}
	return m.ChangePasswordFunc(ctx, tenantID, userID, currentPassword, newPassword)
}

func (m *MockService) RequestMagicLink(ctx context.Context, tenantID string, email string) (string, *identity.User, error) {
	if m.RequestMagicLinkFunc == nil {
		panic("called not defined RequestMagicLinkFunc")
	}
	return m.RequestMagicLinkFunc(ctx, tenantID, email)
}

func (m *MockService) LoginWithMagicLink(ctx context.Context, tenantID string, token string, rc ...event.RequestContext) (*identity.User, error) {
	if m.LoginWithMagicLinkFunc == nil {
		panic("called not defined LoginWithMagicLinkFunc")
	}
	return m.LoginWithMagicLinkFunc(ctx, tenantID, token, rc...)
}

var _ identity.Service = (*MockService)(nil)

func (m *MockService) RequestPasswordReset(ctx context.Context, tenantID string, email string) (string, *identity.User, error) {
	if m.RequestPasswordResetFunc == nil {
		panic("called not defined RequestPasswordResetFunc")
	}
	return m.RequestPasswordResetFunc(ctx, tenantID, email)
}

func (m *MockService) ResetPassword(ctx context.Context, tenantID string, token, newPassword string) error {
	if m.ResetPasswordFunc == nil {
		panic("called not defined ResetPasswordFunc")
	}
	return m.ResetPasswordFunc(ctx, tenantID, token, newPassword)
}

func (m *MockService) RequestEmailVerification(ctx context.Context, tenantID string, userID uuid.UUID) (string, error) {
	if m.RequestEmailVerificationFunc == nil {
		panic("called not defined RequestEmailVerificationFunc")
	}
	return m.RequestEmailVerificationFunc(ctx, tenantID, userID)
}

func (m *MockService) VerifyEmail(ctx context.Context, tenantID string, token string) (*identity.User, error) {
	if m.VerifyEmailFunc == nil {
		panic("called not defined VerifyEmailFunc")
	}
	return m.VerifyEmailFunc(ctx, tenantID, token)
}

func (m *MockService) LinkOrCreateIdentity(ctx context.Context, tenantID string, provider, providerID, email string, emailVerified bool) (*identity.User, error) {
	if m.LinkOrCreateIdentityFunc == nil {
		panic("called not defined LinkOrCreateIdentityFunc")
	}
	return m.LinkOrCreateIdentityFunc(ctx, tenantID, provider, providerID, email, emailVerified)
}

func (m *MockService) Register(ctx context.Context, tenantID string, email, password string) (*identity.User, error) {
	if m.RegisterFunc == nil {
		panic("called not defined RegisterFunc")
	}
	return m.RegisterFunc(ctx, tenantID, email, password)
}

func (m *MockService) Authenticate(ctx context.Context, tenantID string, provider, providerID, password string, _ ...event.RequestContext) (*identity.User, error) {
	if m.AuthenticateFunc == nil {
		panic("called not defined AuthenticateFunc")
	}
	return m.AuthenticateFunc(ctx, tenantID, provider, providerID, password)
}

func (m *MockService) RequestPhoneVerification(ctx context.Context, tenantID string, userID uuid.UUID, phone string) (string, error) {
	if m.RequestPhoneVerificationFunc == nil {
		panic("called not defined RequestPhoneVerificationFunc")
	}
	return m.RequestPhoneVerificationFunc(ctx, tenantID, userID, phone)
}

func (m *MockService) ConfirmPhoneVerification(ctx context.Context, tenantID string, token string) (*identity.User, error) {
	if m.ConfirmPhoneVerificationFunc == nil {
		panic("called not defined ConfirmPhoneVerificationFunc")
	}
	return m.ConfirmPhoneVerificationFunc(ctx, tenantID, token)
}

func (m *MockService) RequestRecoveryEmail(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string) (string, error) {
	if m.RequestRecoveryEmailFunc == nil {
		panic("called not defined RequestRecoveryEmailFunc")
	}
	return m.RequestRecoveryEmailFunc(ctx, tenantID, userID, recoveryEmail)
}

func (m *MockService) ConfirmRecoveryEmail(ctx context.Context, tenantID string, token string) (*identity.User, error) {
	if m.ConfirmRecoveryEmailFunc == nil {
		panic("called not defined ConfirmRecoveryEmailFunc")
	}
	return m.ConfirmRecoveryEmailFunc(ctx, tenantID, token)
}

func (m *MockService) RecoveryChannels(ctx context.Context, tenantID string, userID uuid.UUID) (identity.RecoveryChannels, error) {
	if m.RecoveryChannelsFunc == nil {
		panic("called not defined RecoveryChannelsFunc")
	}
	return m.RecoveryChannelsFunc(ctx, tenantID, userID)
}

func (m *MockService) RequestPasswordResetViaRecovery(ctx context.Context, tenantID string, email string) (string, *identity.User, identity.RecoveryChannels, error) {
	if m.RequestPasswordResetViaRecoveryFunc == nil {
		panic("called not defined RequestPasswordResetViaRecoveryFunc")
	}
	return m.RequestPasswordResetViaRecoveryFunc(ctx, tenantID, email)
}

func (m *MockService) DisableUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if m.DisableUserFunc == nil {
		panic("called not defined DisableUserFunc")
	}
	return m.DisableUserFunc(ctx, tenantID, userID)
}

func (m *MockService) EnableUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if m.EnableUserFunc == nil {
		panic("called not defined EnableUserFunc")
	}
	return m.EnableUserFunc(ctx, tenantID, userID)
}

// PasswordChangeRequired reports whether the credential is flagged for rotation. Because
// LoginHandler and MagicLinkLoginHandler now consult it unconditionally, an unset func defaults
// to the feature-off answer (false, nil) instead of panicking, so handler tests that don't
// exercise rotation need no extra wiring.
func (m *MockService) PasswordChangeRequired(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
	if m.PasswordChangeRequiredFunc == nil {
		return false, nil
	}
	return m.PasswordChangeRequiredFunc(ctx, tenantID, userID)
}

func (m *MockService) SetTemporaryPassword(ctx context.Context, tenantID string, userID uuid.UUID, tempPassword string) error {
	if m.SetTemporaryPasswordFunc == nil {
		panic("called not defined SetTemporaryPasswordFunc")
	}
	return m.SetTemporaryPasswordFunc(ctx, tenantID, userID, tempPassword)
}

func (m *MockService) AdminCreateUser(ctx context.Context, tenantID string, email, tempPassword string) (*identity.User, error) {
	if m.AdminCreateUserFunc == nil {
		panic("called not defined AdminCreateUserFunc")
	}
	return m.AdminCreateUserFunc(ctx, tenantID, email, tempPassword)
}
