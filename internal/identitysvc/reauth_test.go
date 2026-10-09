package identitysvc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JLugagne/egauth/internal/identitysvc"
)

func TestCheckPasswordNeverPassesWithoutAStoredHash(t *testing.T) {
	w := newWorld(t)
	sub := w.createVerified("nopass@example.com", "")
	before := w.hasher.compares.Load()
	if err := w.svc.CheckPassword(context.Background(), sub, "anything at all"); !errors.Is(err, identitysvc.ErrInvalidCredentials) {
		t.Fatalf("CheckPassword without a password row = %v, want invalid_credentials", err)
	}
	if w.hasher.compares.Load() == before {
		t.Fatal("a missing password row must still hash a decoy")
	}
}

func TestCheckPasswordSharesTheLoginLockout(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.createVerified("alice@example.com", "correct horse battery")
	if err := w.svc.CheckPassword(ctx, sub, "correct horse battery"); err != nil {
		t.Fatalf("right password: %v", err)
	}
	for range identitysvc.LockoutThreshold {
		if err := w.svc.CheckPassword(ctx, sub, "wrong"); !errors.Is(err, identitysvc.ErrInvalidCredentials) {
			t.Fatalf("wrong password = %v", err)
		}
	}
	if err := w.svc.CheckPassword(ctx, sub, "correct horse battery"); !errors.Is(err, identitysvc.ErrInvalidCredentials) {
		t.Fatalf("a locked account accepted the right password: %v", err)
	}
	cred, err := w.identity.GetPassword(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if cred.FailedAttempts < identitysvc.LockoutThreshold {
		t.Fatalf("failures charged %d, want %d", cred.FailedAttempts, identitysvc.LockoutThreshold)
	}
	w.clock.Advance(identitysvc.LockoutWindow + 1)
	if err := w.svc.CheckPassword(ctx, sub, "correct horse battery"); err != nil {
		t.Fatalf("after the lockout: %v", err)
	}
	cred, err = w.identity.GetPassword(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if cred.FailedAttempts != 0 {
		t.Fatalf("a success must clear the failures, got %d", cred.FailedAttempts)
	}
}
