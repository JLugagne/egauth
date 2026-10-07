package core

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ForTestCredential is a passkey credential use recorded in ForTestAttrs.
type ForTestCredential struct {
	Factor Factor
	ID     []byte
}

// ForTestAttrs lists every SessionAttrs field for ForTestSessionAttrs.
type ForTestAttrs struct {
	Lineage         uuid.UUID
	Subject         Subject
	Factors         []Factor
	Credentials     []ForTestCredential
	PrimaryAt       time.Time
	SecondAt        time.Time
	Epoch           uint64
	MustChange      bool
	RememberMe      bool
	ReturnTo        string
	Transport       Transport
	Provider        string
	CreatedAt       time.Time
	ClaimsFetchedAt time.Time
}

// String renders f with passkey credential ids replaced by their count, matching the redaction
// contract of every credential-bearing type.
func (f ForTestAttrs) String() string {
	return fmt.Sprintf("ForTestAttrs{Lineage:%s Tenant:%s User:%s Factors:[%s] Credentials:%d Epoch:%d MustChange:%t "+
		"RememberMe:%t Transport:%d Provider:%s}",
		f.Lineage, f.Subject.Tenant, f.Subject.User, forTestFactorCodes(f.Factors), len(f.Credentials), f.Epoch,
		f.MustChange, f.RememberMe, f.Transport, f.Provider)
}

// GoString renders f for %#v with credential ids redacted.
func (f ForTestAttrs) GoString() string { return f.String() }

// LogValue renders f for slog with credential ids redacted.
func (f ForTestAttrs) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("lineage", f.Lineage.String()),
		slog.String("tenant", f.Subject.Tenant.String()),
		slog.String("user", f.Subject.User.String()),
		slog.String("factors", forTestFactorCodes(f.Factors)),
		slog.Int("credentials", len(f.Credentials)),
		slog.Uint64("epoch", f.Epoch),
	)
}

func forTestFactorCodes(fs []Factor) string {
	codes := make([]string, len(fs))
	for i, f := range fs {
		codes[i] = f.Code()
	}
	return strings.Join(codes, " ")
}

// ForTestSessionAttrs builds SessionAttrs without any transition rule, so tests can reach any
// state. Its only allowed caller is internal/principaltest (G6). Factors are put in canonical
// order and times normalised to UTC without a monotonic reading.
func ForTestSessionAttrs(f ForTestAttrs) SessionAttrs {
	a := SessionAttrs{
		version:         codecVersion,
		lineage:         f.Lineage,
		subject:         f.Subject,
		factors:         unionFactors(nil, f.Factors),
		primaryAt:       canonTime(f.PrimaryAt),
		secondAt:        canonTime(f.SecondAt),
		epoch:           f.Epoch,
		mustChange:      f.MustChange,
		remember:        f.RememberMe,
		returnTo:        f.ReturnTo,
		transport:       f.Transport,
		provider:        f.Provider,
		createdAt:       canonTime(f.CreatedAt),
		claimsFetchedAt: canonTime(f.ClaimsFetchedAt),
	}
	for _, c := range f.Credentials {
		a.credentialIDs = append(a.credentialIDs, credentialUse{factor: c.Factor, id: cloneBytes(c.ID)})
	}
	return a
}

// ForTestVerified is one accumulated verification in ForTestPendingFields; its subject is the
// Pending's subject.
type ForTestVerified struct {
	Factors      []Factor
	CredentialID []byte
	Identifies   bool
	Provider     string
	At           time.Time
}

// ForTestPendingFields lists every Pending field for ForTestPending.
type ForTestPendingFields struct {
	Subject     Subject
	EpochAtBind uint64
	Verified    []ForTestVerified
	RememberMe  bool
	ReturnTo    string
	Transport   Transport
	Provider    string
	ReauthOf    uuid.UUID
	BindHash    []byte
	ExpiresAt   time.Time
}

// ForTestPending builds a Pending without any transition rule. Its only allowed caller is
// internal/principaltest (G6). The tenant is the subject's tenant.
func ForTestPending(f ForTestPendingFields) Pending {
	p := Pending{
		version:     codecVersion,
		tenant:      f.Subject.Tenant,
		subject:     f.Subject,
		epochAtBind: f.EpochAtBind,
		remember:    f.RememberMe,
		returnTo:    f.ReturnTo,
		transport:   f.Transport,
		provider:    f.Provider,
		reauthOf:    f.ReauthOf,
		bindHash:    cloneBytes(f.BindHash),
		expiresAt:   canonTime(f.ExpiresAt),
	}
	for _, v := range f.Verified {
		p.verified = append(p.verified, Verified{
			subject:      f.Subject,
			factors:      unionFactors(nil, v.Factors),
			credentialID: cloneBytes(v.CredentialID),
			identifies:   v.Identifies,
			provider:     v.Provider,
			at:           canonTime(v.At),
		})
	}
	return p
}
