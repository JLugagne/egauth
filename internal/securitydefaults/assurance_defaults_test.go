// Assurance-default guards: mechanical, per-family runtime tests that fail if the fail-closed
// default is removed.
//
// Approach: an AST scan can see that an option exists but not that the handler applies it at
// runtime, so these tests exercise the constructors the registry marks credentialEnrollment with
// only their non-assurance wiring (valid cookie key, user resolver) and assert the refusal the
// docs promise. A stub service answers every method with an error, so if a gate stops applying,
// the request proceeds and the status/body stops matching — the test fails either way instead of
// depending on source text. Covered families: passkey registration Begin/Finish, mfa
// enroll/confirm, mfa step-up, and the six identity recovery/email/phone enrollment handlers.
package securitydefaults

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
)

type assuranceStubService struct{}

func (assuranceStubService) EnrollTOTP(context.Context, string, uuid.UUID, string) (*mfa.Enrollment, error) {
	return nil, errAssuranceStubCalled
}

func (assuranceStubService) ConfirmTOTP(context.Context, string, uuid.UUID, string) ([]string, error) {
	return nil, errAssuranceStubCalled
}

func (assuranceStubService) VerifyTOTP(context.Context, string, uuid.UUID, string) error {
	return errAssuranceStubCalled
}

func (assuranceStubService) VerifyRecoveryCode(context.Context, string, uuid.UUID, string) error {
	return errAssuranceStubCalled
}

func (assuranceStubService) RegenerateRecoveryCodes(context.Context, string, uuid.UUID) ([]string, error) {
	return nil, errAssuranceStubCalled
}

func (assuranceStubService) DisableTOTP(context.Context, string, uuid.UUID) error {
	return errAssuranceStubCalled
}

func (assuranceStubService) IsEnrolled(context.Context, string, uuid.UUID) (bool, error) {
	return false, errAssuranceStubCalled
}

func (assuranceStubService) UnlockMFA(context.Context, string, uuid.UUID) error {
	return errAssuranceStubCalled
}

// errAssuranceStubCalled is returned when a handler reaches its service despite the fail-closed
// assurance gate; the resulting non-403 response fails the guard.
var errAssuranceStubCalled = errors.New("the assurance gate must refuse before any service call")

func assurancePost(target, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Same-origin so only the assurance gate can refuse; the CSRF gate runs first in some families.
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

func requireAssuranceRefusal(t *testing.T, label string, h http.Handler, req *http.Request) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("%s: want 403 assurance_required, got %d (%q)", label, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "assurance_required") {
		t.Fatalf("%s: refusal must name assurance_required, got %q", label, rec.Body.String())
	}
}

func assurancePasskeyService(t *testing.T) *passkey.Service {
	t.Helper()
	key := make([]byte, passkey.MinCookieKeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID:           "app.example.com",
		RPDisplayName:  "Example",
		RPOrigins:      []string{"https://app.example.com"},
		CookieKey:      key,
		ChallengeStore: passkeymemory.NewChallengeStore(),
	})
	if err != nil {
		t.Fatalf("passkey.NewService: %v", err)
	}
	return svc
}

// TestPasskeyRegistrationDefaultsToAssuranceRequired pins the passkey registration default: with
// no WithCredentialAssurance (and no opt-out) both Begin and Finish refuse with 403
// assurance_required before touching the ceremony.
func TestPasskeyRegistrationDefaultsToAssuranceRequired(t *testing.T) {
	svc := assurancePasskeyService(t)
	resolve := func(*http.Request) (uuid.UUID, string, string, string, bool) {
		return uuid.Must(uuid.NewV7()), "Ada", "Ada Lovelace", "tenant-1", true
	}
	handlers := map[string]http.HandlerFunc{
		"BeginRegistrationHandler":  passkey.BeginRegistrationHandler(svc, passkey.WithUserResolver(resolve)),
		"FinishRegistrationHandler": passkey.FinishRegistrationHandler(svc, passkey.WithUserResolver(resolve)),
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			requireAssuranceRefusal(t, name, h, assurancePost("https://app.example.com/passkey/register", ""))
		})
	}
}

// TestMFAEnrollmentDefaultsToAssuranceRequired pins the mfa enrollment default: with no
// WithCredentialAssurance (and no opt-out) Enroll and Confirm refuse with 403
// assurance_required before calling the service.
func TestMFAEnrollmentDefaultsToAssuranceRequired(t *testing.T) {
	resolve := func(*http.Request) (uuid.UUID, string, bool) {
		return uuid.Must(uuid.NewV7()), "tenant-1", true
	}
	handlers := map[string]http.HandlerFunc{
		"EnrollHandler":  mfa.EnrollHandler(assuranceStubService{}, mfa.WithUserResolver(resolve)),
		"ConfirmHandler": mfa.ConfirmHandler(assuranceStubService{}, mfa.WithUserResolver(resolve)),
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			requireAssuranceRefusal(t, name, h, assurancePost("https://app.example.com/mfa/enroll", "account=ada@example.com"))
		})
	}
}

// TestMFAStepUpDefaultsToMisconfigured pins the step-up default: with no
// WithSessionStateResolver (and no opt-out) the handler refuses with 500 misconfigured instead
// of minting the renewable pair from the interim token's own subject.
func TestMFAStepUpDefaultsToMisconfigured(t *testing.T) {
	resolve := func(*http.Request) (uuid.UUID, string, bool) {
		return uuid.Must(uuid.NewV7()), "tenant-1", true
	}
	h := mfa.StepUpHandler[struct{}](nil, nil, nil, mfa.WithUserResolver(resolve))
	rec := httptest.NewRecorder()
	h(rec, assurancePost("https://app.example.com/mfa/step-up", "code=123456"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("step-up with no session-state resolver must fail closed with 500, got %d (%q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "misconfigured") {
		t.Fatalf("the refusal must name misconfigured, got %q", rec.Body.String())
	}
}

// TestIdentityRecoveryEnrollmentDefaultsToDenyInterim pins the identity default: the six
// enrollment handlers apply tokens.DenyInterim with no options, so an interim (pre-MFA) access
// session is refused with 403 assurance_required. The interim context is produced through the
// exported tokens.ContextMiddleware so the test asserts the real gate contract.
func TestIdentityRecoveryEnrollmentDefaultsToDenyInterim(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	verifier := &issuertest.MockVerifier[struct{}]{
		VerifyAccessTokenForTenantFunc: func(context.Context, string, string) (*tokens.Claims[struct{}], error) {
			return &tokens.Claims[struct{}]{
				Subject:  uid,
				TenantID: "tenant-1",
				Interim:  true,
				AMR:      []string{"pwd"},
			}, nil
		},
	}
	stub := &servicetest.MockService{
		RequestRecoveryEmailFunc:     func(context.Context, string, uuid.UUID, string) (string, error) { return "", nil },
		ConfirmRecoveryEmailFunc:     func(context.Context, string, string) (*identity.User, error) { return &identity.User{ID: uid}, nil },
		RequestEmailChangeFunc:       func(context.Context, string, uuid.UUID, string) (string, error) { return "", nil },
		ConfirmEmailChangeFunc:       func(context.Context, string, string) (*identity.User, error) { return &identity.User{ID: uid}, nil },
		RequestPhoneVerificationFunc: func(context.Context, string, uuid.UUID, string) (string, error) { return "", nil },
		ConfirmPhoneVerificationFunc: func(context.Context, string, string) (*identity.User, error) { return &identity.User{ID: uid}, nil },
	}
	user := func(*http.Request) (*identity.User, bool) { return &identity.User{ID: uid}, true }
	inner := map[string]http.Handler{
		"RequestRecoveryEmailHandler":     identity.RequestRecoveryEmailHandler(stub, identity.Mailer{}, identity.WithUserResolver(user)),
		"ConfirmRecoveryEmailHandler":     identity.ConfirmRecoveryEmailHandler(stub, identity.WithUserResolver(user)),
		"RequestEmailChangeHandler":       identity.RequestEmailChangeHandler(stub, identity.Mailer{}, identity.WithUserResolver(user)),
		"ConfirmEmailChangeHandler":       identity.ConfirmEmailChangeHandler(stub, identity.WithUserResolver(user)),
		"RequestPhoneVerificationHandler": identity.RequestPhoneVerificationHandler(stub, identity.SMSSender{}, identity.WithUserResolver(user)),
		"ConfirmPhoneVerificationHandler": identity.ConfirmPhoneVerificationHandler(stub, identity.WithUserResolver(user)),
	}
	for name, h := range inner {
		t.Run(name, func(t *testing.T) {
			req := assurancePost("https://app.example.com/account/enrollment", "recovery_email=new@example.com")
			req.Header.Set("Authorization", "Bearer interim-token")
			req.Header.Set("Origin", "https://app.example.com")
			requireAssuranceRefusal(t, name, tokens.ContextMiddleware[struct{}](verifier, h), req)
		})
	}
}
