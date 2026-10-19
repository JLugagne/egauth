package identitysvc_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/passwords"
)

type overloadedHasher struct {
	*fakeHasher
}

func (overloadedHasher) Compare(ctx context.Context, _ passwords.PHC, _ string) error {
	return context.DeadlineExceeded
}

func TestALoginWhoseComparisonTimesOutIsAnOutageNotAWrongPassword(t *testing.T) {
	w := newWorld(t)
	w.createVerified("busy@example.com", goodPass)
	w = w.build(func(c *identitysvc.Config) { c.Hasher = overloadedHasher{&fakeHasher{}} })
	if code, body := login(w, "busy@example.com", goodPass); code != http.StatusServiceUnavailable {
		t.Fatalf("login whose hash comparison ran out of time = %d %s, want 503: the user must not be told the password is wrong", code, body)
	}
	if code, body := login(w, "nobody@example.com", goodPass); code != http.StatusServiceUnavailable {
		t.Fatalf("unknown account under the same overload = %d %s, want 503 like a known one", code, body)
	}
}
