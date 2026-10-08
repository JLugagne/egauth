package identitysvc_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
)

func TestAccountStateReflectsTheStore(t *testing.T) {
	var unv *unverifiedStore
	w := newWorldWrapping(t, func(s identity.Store) identity.Store {
		unv = newUnverifiedStore(s)
		return unv
	})
	ctx := context.Background()
	unknown, err := w.svc.AccountState(ctx, core.Subject{User: uuid.New()})
	if err != nil || unknown.Exists() || unknown.Usable() {
		t.Fatalf("unknown subject = %+v %v; the zero state fails closed", unknown, err)
	}
	sub := w.createVerified("kim@example.com", goodPass)
	st, err := w.svc.AccountState(ctx, sub)
	if err != nil || !st.Usable() || !st.EmailVerified() || st.MustChange() || st.Epoch() != w.epoch(sub) {
		t.Fatalf("live account = %+v %v", st, err)
	}
	if _, err := w.identity.Apply(ctx, identity.SetDisabledState{Subject: sub, Disable: true}); err != nil {
		t.Fatal(err)
	}
	st, _ = w.svc.AccountState(ctx, sub)
	if !st.Disabled() || st.Usable() || st.Epoch() != w.epoch(sub) {
		t.Fatalf("disabled account = %+v", st)
	}
	if _, err := w.identity.Apply(ctx, identity.Tombstone{Subject: sub}); err != nil {
		t.Fatal(err)
	}
	st, _ = w.svc.AccountState(ctx, sub)
	if !st.Deleted() || st.Usable() {
		t.Fatalf("deleted account = %+v", st)
	}
	other := w.createVerified("lea@example.com", goodPass)
	unv.setUnverified(other)
	st, _ = w.svc.AccountState(ctx, other)
	if st.EmailVerified() {
		t.Fatal("unverified email reported verified")
	}
	unv.getErr = errors.New("database down")
	if _, err := w.svc.AccountState(ctx, other); !errors.Is(err, httpx.ErrUnavailable) {
		t.Fatalf("store failure = %v, want httpx.ErrUnavailable", err)
	}
}

type recordingDispatcher struct {
	mu    sync.Mutex
	items []identity.OutboxItem
}

func (d *recordingDispatcher) DispatchOutbox(_ context.Context, items []identity.OutboxItem) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.items = append(d.items, items...)
}

func TestApplyBumpsTheEpochAndHandsTheOutboxToTheDispatcher(t *testing.T) {
	d := &recordingDispatcher{}
	w := newWorld(t, func(c *identitysvc.Config) { c.Dispatcher = d })
	sub := w.createVerified("max@example.com", goodPass)
	before := w.epoch(sub)
	a, err := w.svc.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorTOTPEnrolled})
	if err != nil {
		t.Fatal(err)
	}
	if a.NewEpoch != before+1 || w.epoch(sub) != a.NewEpoch {
		t.Fatalf("epoch %d -> %d", before, a.NewEpoch)
	}
	if len(d.items) == 0 || len(d.items) != len(a.Outbox) || d.items[0].Event != identity.EventFactorsChanged {
		t.Fatalf("dispatched = %+v", d.items)
	}
	if _, err := w.svc.Apply(context.Background(), identity.SetMustChange{}); !errors.Is(err, identity.ErrInvalidMutation) {
		t.Fatalf("invalid mutation = %v", err)
	}
}

func TestVerifyEmailOwnershipNeverWipesAVerifiedAccount(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.createVerified("ned@example.com", goodPass)
	if err := w.passkeys.Save(ctx, passkey.Credential{Subject: sub, ID: passkey.CredentialID("k"), PublicKey: []byte{1}, Discoverable: passkey.Confirmed}); err != nil {
		t.Fatal(err)
	}
	epoch := w.epoch(sub)
	if _, err := w.svc.VerifyEmailOwnership(ctx, sub, identity.PasswordHash{}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("verified account = %v, want store.ErrConflict", err)
	}
	if creds, _ := w.passkeys.List(ctx, sub); len(creds) != 1 || w.epoch(sub) != epoch {
		t.Fatal("a refused verification touched the account")
	}
	if _, err := w.svc.VerifyEmailOwnership(ctx, core.Subject{User: uuid.New()}, identity.PasswordHash{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown subject = %v", err)
	}
}

func TestRacingVerificationNeverWipesAFactorEnrolledAfterVerification(t *testing.T) {
	cases := []struct {
		name   string
		pause  identity.FactorChange
		enrol  func(w *world, sub core.Subject) error
		exists func(w *world, sub core.Subject) bool
	}{
		{
			name:  "passkey",
			pause: identity.FactorPasskeyRemoved,
			enrol: func(w *world, sub core.Subject) error {
				return w.passkeys.Save(context.Background(), passkey.Credential{Subject: sub, ID: passkey.CredentialID("owner-key"), PublicKey: []byte{1}, Discoverable: passkey.Confirmed})
			},
			exists: func(w *world, sub core.Subject) bool {
				creds, _ := w.passkeys.List(context.Background(), sub)
				return len(creds) == 1
			},
		},
		{
			name:  "totp",
			pause: identity.FactorTOTPRemoved,
			enrol: func(w *world, sub core.Subject) error {
				return w.mfa.SaveTOTP(context.Background(), mfa.Enrollment{Subject: sub, Sealed: []byte{1}, AADVersion: mfa.AADVersionCurrent})
			},
			exists: func(w *world, sub core.Subject) bool {
				_, err := w.mfa.GetTOTP(context.Background(), sub)
				return err == nil
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var unv *unverifiedStore
			w := newWorldWrapping(t, func(s identity.Store) identity.Store {
				unv = newUnverifiedStore(s)
				return unv
			})
			ctx := context.Background()
			sub := w.createVerified("racer@example.com", "")
			unv.setUnverified(sub)
			var fired atomic.Bool
			var first error
			unv.onApply(func(m identity.Mutation) {
				bump, ok := m.(identity.BumpEpoch)
				if !ok || bump.Change != c.pause || !fired.CompareAndSwap(false, true) {
					return
				}
				if _, first = w.svc.VerifyEmailOwnership(ctx, sub, identity.NewPasswordHash("$fake$"+goodPass)); first != nil {
					return
				}
				first = c.enrol(w, sub)
			})
			_, err := w.svc.VerifyEmailOwnership(ctx, sub, identity.PasswordHash{})
			if first != nil {
				t.Fatalf("the winning proof failed: %v", first)
			}
			if !errors.Is(err, store.ErrConflict) {
				t.Fatalf("the losing proof = %v, want store.ErrConflict", err)
			}
			if !c.exists(w, sub) {
				t.Fatal("a racing proof wiped a factor enrolled after the account was verified")
			}
		})
	}
}
