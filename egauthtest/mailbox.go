package egauthtest

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/JLugagne/egauth"
)

// Mail is one message a Mailbox captured. Link, Code and RevertLink are the working secrets, so
// never log a Mail.
type Mail struct {
	Kind       string
	To         string
	Link       string
	Code       string
	RevertLink string
	DeliveryID string
}

// String renders m with its secrets redacted.
func (m Mail) String() string {
	return "Mail{Kind:" + m.Kind + " To:" + m.To + " Link:REDACTED Code:REDACTED RevertLink:REDACTED}"
}

// GoString renders m for %#v with its secrets redacted.
func (m Mail) GoString() string { return m.String() }

// LogValue renders m for slog with its secrets redacted.
func (m Mail) LogValue() slog.Value {
	return slog.GroupValue(slog.String("kind", m.Kind), slog.String("to", m.To), slog.String("secrets", "REDACTED"))
}

// MarshalJSON renders m with its secrets redacted.
func (m Mail) MarshalJSON() ([]byte, error) {
	const r = "REDACTED"
	return json.Marshal(struct{ Kind, To, Link, Code, RevertLink, DeliveryID string }{m.Kind, m.To, r, r, r, m.DeliveryID})
}

// Mailbox is an egauth.EmailDeliverer that records every message instead of sending it. It is safe
// for concurrent use.
type Mailbox struct {
	mu   sync.Mutex
	mail []Mail
}

var _ egauth.EmailDeliverer = (*Mailbox)(nil)

// Messages returns a copy of the captured messages in delivery order.
func (m *Mailbox) Messages() []Mail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Mail(nil), m.mail...)
}

// Last returns the most recent message of kind, and false when there is none. Kind is the method
// name of egauth.EmailDeliverer, for example "PasswordResetLink".
func (m *Mailbox) Last(kind string) (Mail, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.mail) - 1; i >= 0; i-- {
		if m.mail[i].Kind == kind {
			return m.mail[i], true
		}
	}
	return Mail{}, false
}

func (m *Mailbox) put(x Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mail = append(m.mail, x)
	return nil
}

func (m *Mailbox) link(kind string, l egauth.LinkMessage) error {
	return m.put(Mail{Kind: kind, To: l.To, Link: l.Link, DeliveryID: l.DeliveryID.String()})
}

func (m *Mailbox) RegistrationLink(_ context.Context, l egauth.LinkMessage) error {
	return m.link("RegistrationLink", l)
}

func (m *Mailbox) AccountExistsNotice(_ context.Context, n egauth.NoticeMessage) error {
	return m.put(Mail{Kind: "AccountExistsNotice", To: n.To, DeliveryID: n.DeliveryID.String()})
}

func (m *Mailbox) PasswordResetLink(_ context.Context, l egauth.LinkMessage) error {
	return m.link("PasswordResetLink", l)
}

func (m *Mailbox) MagicLink(_ context.Context, l egauth.LinkMessage) error {
	return m.link("MagicLink", l)
}

func (m *Mailbox) LoginCode(_ context.Context, c egauth.CodeMessage) error {
	return m.put(Mail{Kind: "LoginCode", To: c.To, Code: c.Code, DeliveryID: c.DeliveryID.String()})
}

func (m *Mailbox) EmailVerificationLink(_ context.Context, l egauth.LinkMessage) error {
	return m.link("EmailVerificationLink", l)
}

func (m *Mailbox) EmailChangeLink(_ context.Context, l egauth.LinkMessage) error {
	return m.link("EmailChangeLink", l)
}

func (m *Mailbox) RecoveryEmailLink(_ context.Context, l egauth.LinkMessage) error {
	return m.link("RecoveryEmailLink", l)
}

func (m *Mailbox) SecurityNotice(_ context.Context, n egauth.SecurityNoticeMessage) error {
	return m.put(Mail{Kind: "SecurityNotice", To: n.To, RevertLink: n.RevertLink, DeliveryID: n.DeliveryID.String()})
}
