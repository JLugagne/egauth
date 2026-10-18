package identitysvc_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
)

type stuckMailer struct {
	*fakeMailer
	entered chan struct{}
}

func (m *stuckMailer) RegistrationLink(context.Context, identitysvc.LinkMessage) error {
	close(m.entered)
	select {}
}

func TestCloseIsBoundedByADelivererThatNeverReturns(t *testing.T) {
	m := &stuckMailer{fakeMailer: &fakeMailer{}, entered: make(chan struct{})}
	w := newWorld(t, func(c *identitysvc.Config) { c.Mailer = m })
	w.do(req{path: routes.Register, fields: map[string]string{"identifier": "stuck@example.com", "password": goodPass}})
	select {
	case <-m.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the registration link was never handed to the mailer")
	}
	closed := make(chan struct{})
	go func() {
		_ = w.svc.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(20 * time.Second):
		t.Fatal("Close still waits on a deliverer that never returns: shutdown has no bound")
	}
}
