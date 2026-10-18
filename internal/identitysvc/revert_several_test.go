package identitysvc_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
)

func TestRevertingSeveralNoticesKeepsTheOwnersFactorAndTheAccountUsable(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	savePasskey(t, w, sub, "owner-key", w.clock.Now())
	w.clock.Advance(24 * time.Hour)
	var links []string
	for _, id := range []string{"k1", "k2", "k3"} {
		addHijackerPasskey(t, w, sub, id)
		links = append(links, noticeTo(t, w, "owner@example.com", identitysvc.SecurityFactorsChanged).RevertLink)
		w.clock.Advance(time.Hour)
	}
	for i, l := range links {
		rec := w.call(routes.SecurityRevert, "", map[string]string{routes.FieldToken: tokenOf(t, l)})
		if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
			t.Fatalf("revert %d answered %d", i+1, rec.Code)
		}
		w.clock.Advance(time.Minute)
	}
	keys := passkeyIDs(t, w, sub)
	if keys["k1"] || keys["k2"] || keys["k3"] || !keys["owner-key"] {
		t.Fatalf("passkeys after the reverts = %v, want only the owner's", keys)
	}
	if !w.user(sub).DisabledAt.IsZero() {
		t.Fatalf("the owner reverted three hijacker notices and the account ended disabled although owner-key survives: %v", keys)
	}
}
