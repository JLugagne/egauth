package egauth_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/journeytest"
)

// TestRecipientLimit_CodeSendersAreBudgetedPerRecipient pins the per-recipient budget of the
// endpoints that send a code or a link to a caller-chosen address: rotating the client address
// must not let one account text or mail the same recipient more than the CodeRequestIdentifier
// burst (F-HGR-001, SMS and e-mail bombing).
func TestRecipientLimit_CodeSendersAreBudgetedPerRecipient(t *testing.T) {
	w := journeytest.NewWorld(t, journeytest.Settings{})
	email := w.FreshEmail("smsvictim")
	w.SeedUser(email, false)
	c := w.NewClient()
	c.Login(email, false)

	const (
		requests          = 21 // one more than the per-client burst of CodeRequestClient
		perRecipientBurst = 5  // limiter.CodeRequestIdentifier
	)
	send := func(path, field, recipient string, ok ...int) int {
		t.Helper()
		accepted := 0
		for i := 0; i < requests; i++ {
			res := c.Do(journeytest.Req{
				Method: http.MethodPost,
				Path:   "/auth" + path,
				JSON:   map[string]any{field: recipient},
				Remote: c.FreshRemote(),
			})
			switch {
			case res.Status == http.StatusTooManyRequests:
			case containsStatus(ok, res.Status):
				accepted++
			default:
				t.Fatalf("%s request %d: status %d body %s", path, i, res.Status, res.Body)
			}
		}
		if accepted > perRecipientBurst {
			t.Errorf("%s accepted %d requests for %s from distinct client addresses; the per-recipient budget is %d",
				path, accepted, recipient, perRecipientBurst)
		}
		return accepted
	}

	texts := send(egauth.PathPhoneVerifyRequest, egauth.FieldPhone, "+14155550123", http.StatusOK)
	mails := send(egauth.PathEmailChange, egauth.FieldEmail, "victim-change@example.org", http.StatusOK, http.StatusAccepted)
	send(egauth.PathRecoveryEmail, egauth.FieldEmail, "victim-recovery@example.org", http.StatusOK, http.StatusAccepted)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (w.TextCount("PhoneVerificationCode") < texts || w.MailCount("EmailChangeLink") < mails) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := w.TextCount("PhoneVerificationCode"); got > perRecipientBurst {
		t.Errorf("%d verification texts were sent to one number; the per-recipient budget is %d", got, perRecipientBurst)
	}
	if got := w.MailCount("EmailChangeLink"); got > perRecipientBurst {
		t.Errorf("%d e-mail change links were sent to one address; the per-recipient budget is %d", got, perRecipientBurst)
	}
}

func containsStatus(set []int, status int) bool {
	for _, s := range set {
		if s == status {
			return true
		}
	}
	return false
}
