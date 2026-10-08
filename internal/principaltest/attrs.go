package principaltest

import (
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
)

// Credential is a passkey credential use recorded in a Spec.
type Credential struct {
	Factor core.Factor
	ID     []byte
}

// Spec lists every SessionAttrs field for Attrs.
type Spec struct {
	Lineage         uuid.UUID
	Subject         core.Subject
	Factors         []core.Factor
	PasskeyUses     []Credential
	PrimaryAt       time.Time
	SecondAt        time.Time
	Epoch           uint64
	MustChange      bool
	RememberMe      bool
	ReturnTo        string
	Transport       core.Transport
	Provider        string
	CreatedAt       time.Time
	ClaimsFetchedAt time.Time
}

// Attrs builds SessionAttrs from s without any transition rule, so tests can reach any state.
func Attrs(s Spec) core.SessionAttrs {
	f := core.ForTestAttrs{
		Lineage:         s.Lineage,
		Subject:         s.Subject,
		Factors:         s.Factors,
		PrimaryAt:       s.PrimaryAt,
		SecondAt:        s.SecondAt,
		Epoch:           s.Epoch,
		MustChange:      s.MustChange,
		RememberMe:      s.RememberMe,
		ReturnTo:        s.ReturnTo,
		Transport:       s.Transport,
		Provider:        s.Provider,
		CreatedAt:       s.CreatedAt,
		ClaimsFetchedAt: s.ClaimsFetchedAt,
	}
	for _, c := range s.PasskeyUses {
		f.Credentials = append(f.Credentials, core.ForTestCredential{Factor: c.Factor, ID: c.ID})
	}
	return core.ForTestSessionAttrs(f)
}
