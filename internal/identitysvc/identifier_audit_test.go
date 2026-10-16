package identitysvc_test

import (
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/identitysvc"
)

func countOf(w *acctWorld, t event.Type) int {
	n := 0
	for _, got := range w.sink.types() {
		if got == t {
			n++
		}
	}
	return n
}

func TestEmailChangeAndItsRevertEachEmitOneIdentifierChanged(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "hijacker@example.com")
	if got := countOf(w, event.IdentifierChanged); got != 1 {
		t.Fatalf("identifier.changed after the email change = %d, want 1", got)
	}
	notice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	if got := revert(w, notice.RevertLink); got != 200 {
		t.Fatalf("revert answered %d", got)
	}
	if got := countOf(w, event.IdentifierChanged); got != 2 {
		t.Fatalf("identifier.changed after the revert = %d, want 2: the restore must be audited", got)
	}
}
