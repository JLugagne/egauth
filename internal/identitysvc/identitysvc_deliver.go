package identitysvc

import (
	"context"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/delivery"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/store/identity"
)

type deliveries struct {
	mailer Mailer
	pool   *delivery.Pool
}

func newDeliveries(m Mailer, a httpx.Audit) *deliveries {
	return &deliveries{mailer: m, pool: delivery.New(a)}
}

func (d *deliveries) enqueue(ctx context.Context, t core.TenantID, id uuid.UUID, send func(context.Context) error) {
	d.pool.Enqueue(ctx, t, id, send)
}

func (d *deliveries) close() { d.pool.Close() }

func (s *Service) sendRegistrationLink(ctx context.Context, m LinkMessage) {
	m.DeliveryID = uuid.New()
	s.mail.enqueue(ctx, m.Tenant, m.DeliveryID, func(c context.Context) error {
		return s.mail.mailer.RegistrationLink(c, m)
	})
}

func (s *Service) sendAccountExists(ctx context.Context, m NoticeMessage) {
	m.DeliveryID = uuid.New()
	s.mail.enqueue(ctx, m.Tenant, m.DeliveryID, func(c context.Context) error {
		return s.mail.mailer.AccountExistsNotice(c, m)
	})
}

func (s *Service) sendReset(ctx context.Context, p core.Pending, u identity.User, st core.AccountState) {
	if s.noReset {
		return
	}
	id := uuid.New()
	s.mail.enqueue(ctx, u.Subject.Tenant, id, func(c context.Context) error {
		m, err := s.putReset(c, p, u, st)
		if err != nil {
			_ = s.audit.Emit(c, event.DeliveryFailed, scopeOf(u.Subject), audit.Detail{Reason: "password_reset"}, err,
				audit.A(event.KeyDeliveryID, id.String()))
			return nil
		}
		m.DeliveryID = id
		return s.mail.mailer.PasswordResetLink(c, m)
	})
}
