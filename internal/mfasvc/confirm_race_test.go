package mfasvc_test

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/store/mfa"
)

type reEnrollingStore struct {
	mfa.Store
	mu    sync.Mutex
	calls int
	at    int
	hook  func()
}

func (s *reEnrollingStore) GetTOTP(ctx context.Context, sub core.Subject) (mfa.Enrollment, error) {
	e, err := s.Store.GetTOTP(ctx, sub)
	s.mu.Lock()
	s.calls++
	var h func()
	if s.hook != nil && s.calls == s.at {
		h, s.hook = s.hook, nil
	}
	s.mu.Unlock()
	if h != nil {
		h()
	}
	return e, err
}

func (s *reEnrollingStore) arm(at int, hook func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls, s.at, s.hook = 0, at, hook
}

func (w *world) raceStore() *reEnrollingStore {
	rs := &reEnrollingStore{Store: w.mfa}
	w.mfa = rs
	w.build()
	return rs
}

func randomSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func (w *world) saveUnconfirmed(sub core.Subject, secret string) {
	w.t.Helper()
	ctx := context.Background()
	ref, err := sealing.TOTPSecret(sub)
	if err != nil {
		w.t.Fatal(err)
	}
	sealed, err := sealing.Seal(ctx, w.kek, ref, []byte(secret))
	if err != nil {
		w.t.Fatal(err)
	}
	err = w.mfa.SaveTOTP(ctx, mfa.Enrollment{
		Subject:    sub,
		Sealed:     sealed,
		AADVersion: mfa.AADVersionCurrent,
		CreatedAt:  w.clock.Now(),
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) acceptsTOTPOf(sub core.Subject, secret string) bool {
	w.t.Helper()
	_, err := w.svc.Verify(context.Background(), sub, core.FactorTOTP, totpAt(w.t, secret, w.clock.Now()))
	return err == nil
}

func TestConfirmConfirmsTheSecretTheCodeProvedWhenReEnrolledBeforeVerification(t *testing.T) {
	w := newWorld(t)
	rs := w.raceStore()
	sub := w.user("ann@example.com")
	tok := w.session(sub)
	first := w.enroll(tok).Secret
	second := randomSecret(t)
	rs.arm(1, func() { w.saveUnconfirmed(sub, second) })
	rec := w.post(tok, routes.MFATOTPConfirm, map[string]string{routes.FieldCode: totpAt(t, second, w.clock.Now())})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	w.clock.Advance(30 * time.Second)
	if w.acceptsTOTPOf(sub, first) {
		t.Fatal("confirm proved possession of the second secret but confirmed the never-proven first one")
	}
	w.clock.Advance(30 * time.Second)
	if !w.acceptsTOTPOf(sub, second) {
		t.Fatal("the secret whose code was presented at confirm is not the confirmed one")
	}
}

func TestConfirmConfirmsTheSecretTheCodeProvedWhenReEnrolledAfterVerification(t *testing.T) {
	w := newWorld(t)
	rs := w.raceStore()
	sub := w.user("ann@example.com")
	tok := w.session(sub)
	first := w.enroll(tok).Secret
	late := randomSecret(t)
	rs.arm(2, func() { w.saveUnconfirmed(sub, late) })
	rec := w.post(tok, routes.MFATOTPConfirm, map[string]string{routes.FieldCode: totpAt(t, first, w.clock.Now())})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	w.clock.Advance(30 * time.Second)
	if w.acceptsTOTPOf(sub, late) {
		t.Fatal("confirm confirmed a secret saved after the code was checked")
	}
	w.clock.Advance(30 * time.Second)
	if !w.acceptsTOTPOf(sub, first) {
		t.Fatal("the proven secret is not the confirmed one")
	}
}
