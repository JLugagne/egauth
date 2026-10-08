package egauthtest

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/principal"
)

// PrincipalSpec describes the Principal NewPrincipal builds. Every zero field takes a default: the
// single tenant and a fixed user, the password factor, cookie transport, and ReferenceTime for
// PrimaryAt, CreatedAt and ClaimsFetchedAt.
type PrincipalSpec struct {
	Subject         principal.Subject
	Lineage         uuid.UUID
	UsedFactors     []principal.Factor
	PasskeyID       []byte
	SecurityEpoch   uint64
	MustChange      bool
	Remembered      bool
	ReturnPath      string
	Transport       principal.Transport
	Provider        string
	PrimaryAt       time.Time
	SecondAt        time.Time
	CreatedAt       time.Time
	ClaimsFetchedAt time.Time
	Roles           []string
	Groups          []string
	Scopes          []string
	Custom          any
	Machine         *egauth.APIKeyInfo
}

var (
	defaultUser    = uuid.MustParse("5d0e1f2a-3b4c-4d5e-8f6a-7b8c9d0e1f2a")
	defaultLineage = uuid.MustParse("1e2d3c4b-5a69-4788-9a0b-c1d2e3f4a5b6")
	defaultKey     = uuid.MustParse("9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d")
)

// NewPrincipal builds the Principal described by spec without running any route gate: an API-key
// Principal when spec.Machine is set, a session Principal otherwise. Use egauth.Principal's zero
// value for Anonymous. It fails when Custom is not a C or the spec cannot form a caller.
func NewPrincipal[C any](spec PrincipalSpec) (egauth.Principal[C], error) {
	claims := egauth.AppClaims[C]{Roles: spec.Roles, Groups: spec.Groups, Scopes: spec.Scopes}
	if spec.Custom != nil {
		c, ok := spec.Custom.(C)
		if !ok {
			return egauth.Principal[C]{}, errors.New("egauthtest: PrincipalSpec.Custom is not the claims type of the Principal")
		}
		claims.Custom = c
	}
	if spec.Subject.IsZero() {
		spec.Subject.User = defaultUser
	}
	if spec.Machine != nil {
		return egauth.TestHookAPIKeyPrincipal(apiKeyInfo(spec), claims)
	}
	return egauth.TestHookSessionPrincipal(sessionAttrs(spec), claims)
}

func apiKeyInfo(spec PrincipalSpec) egauth.APIKeyInfo {
	info := *spec.Machine
	if info.Owner.IsZero() {
		info.Owner = spec.Subject
	}
	if info.ID == uuid.Nil {
		info.ID = defaultKey
	}
	if info.CreatedAt.IsZero() {
		info.CreatedAt = ReferenceTime()
	}
	return info
}

func sessionAttrs(spec PrincipalSpec) principal.SessionAttrs {
	s := principaltest.Spec{
		Lineage:         spec.Lineage,
		Subject:         spec.Subject,
		Factors:         spec.UsedFactors,
		Epoch:           spec.SecurityEpoch,
		MustChange:      spec.MustChange,
		RememberMe:      spec.Remembered,
		ReturnTo:        spec.ReturnPath,
		Transport:       spec.Transport,
		Provider:        spec.Provider,
		PrimaryAt:       or(spec.PrimaryAt, ReferenceTime()),
		SecondAt:        spec.SecondAt,
		CreatedAt:       or(spec.CreatedAt, ReferenceTime()),
		ClaimsFetchedAt: or(spec.ClaimsFetchedAt, ReferenceTime()),
	}
	if s.Lineage == uuid.Nil {
		s.Lineage = defaultLineage
	}
	if len(s.Factors) == 0 {
		s.Factors = []principal.Factor{principal.FactorPassword}
	}
	if s.Transport == 0 {
		s.Transport = principal.TransportCookies
	}
	if len(spec.PasskeyID) > 0 {
		s.PasskeyUses = []principaltest.Credential{{Factor: principal.FactorPasskey, ID: spec.PasskeyID}}
	}
	return principaltest.Attrs(s)
}

func or(t, fallback time.Time) time.Time {
	if t.IsZero() {
		return fallback
	}
	return t
}
