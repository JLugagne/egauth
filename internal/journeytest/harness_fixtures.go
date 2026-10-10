package journeytest

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
)

// TOTPCode returns the RFC 6238 code (SHA-1, 6 digits, 30 s) of the base32 secret at time at.
func TOTPCode(secret string, at time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "000000"
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", code)
}

// WaitMail waits for the n-th message of kind (the method name of EmailDeliverer) to be delivered
// and returns it; deliveries run from the lifecycle outbox, so they are asynchronous. It fails t after
// five seconds.
func (w *World) WaitMail(kind string, n int) egauthtest.Mail {
	w.T.Helper()
	deadline := time.After(5 * time.Second)
	for {
		var of []egauthtest.Mail
		for _, m := range w.Mailbox.Messages() {
			if m.Kind == kind {
				of = append(of, m)
			}
		}
		if len(of) >= n {
			return of[n-1]
		}
		select {
		case <-deadline:
			w.T.Fatalf("journeytest: no %s mail number %d was delivered", kind, n)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// MailCount returns how many messages of kind were delivered so far.
func (w *World) MailCount(kind string) int {
	n := 0
	for _, m := range w.Mailbox.Messages() {
		if m.Kind == kind {
			n++
		}
	}
	return n
}

// TextCount returns how many texts of kind were captured so far.
func (w *World) TextCount(kind string) int {
	n := 0
	for _, m := range w.SMS.Messages() {
		if m.Kind == kind {
			n++
		}
	}
	return n
}

// WaitText waits for the n-th text of kind (the method name of SMSDeliverer) and returns it; it
// fails t after five seconds.
func (w *World) WaitText(kind string, n int) Text {
	w.T.Helper()
	deadline := time.After(5 * time.Second)
	for {
		var of []Text
		for _, m := range w.SMS.Messages() {
			if m.Kind == kind {
				of = append(of, m)
			}
		}
		if len(of) >= n {
			return of[n-1]
		}
		select {
		case <-deadline:
			w.T.Fatalf("journeytest: no %s text number %d was delivered", kind, n)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Post sends a JSON POST to the auth endpoint at path (a Path* constant).
func (c *Client) Post(path string, fields map[string]any) *Resp {
	c.T.Helper()
	return c.Do(Req{Method: http.MethodPost, Path: "/auth" + path, JSON: fields})
}

// EnrollTOTP enrolls and confirms TOTP for the signed-in subject through the endpoints and returns
// the secret and the recovery codes. The clock is advanced one period afterwards so that a login
// code is never a replay of the confirmation code.
func (c *Client) EnrollTOTP(w *World) (secret string, recovery []string) {
	c.T.Helper()
	r := c.Post(egauth.PathMFATOTPEnroll, nil)
	secret = r.Field("secret")
	if r.Status != http.StatusOK || secret == "" {
		c.T.Fatalf("journeytest: TOTP enrollment: %s", Describe(r))
	}
	r = c.Post(egauth.PathMFATOTPConfirm, map[string]any{egauth.FieldCode: TOTPCode(secret, w.Clock.Now())})
	if r.Status != http.StatusOK {
		c.T.Fatalf("journeytest: TOTP confirmation: %s", Describe(r))
	}
	if codes, ok := r.JSONBody(c.T)["recovery_codes"].([]any); ok {
		for _, v := range codes {
			recovery = append(recovery, fmt.Sprint(v))
		}
	}
	w.Clock.Advance(30 * time.Second)
	return secret, recovery
}

// ChallengeTOTP answers a pending MFA flow with the TOTP code of secret at the world's clock. Under
// the Bearer transport it presents the flow handle the last login response carried; under cookies
// the flow cookie in the jar is the handle.
func (c *Client) ChallengeTOTP(w *World, secret string) *Resp {
	c.T.Helper()
	f := map[string]any{egauth.FieldFactor: "totp", egauth.FieldCode: TOTPCode(secret, w.Clock.Now())}
	if c.flow != "" {
		f[egauth.FieldFlow] = c.flow
	}
	res := c.Post(egauth.PathMFAChallenge, f)
	c.keepTokens(res)
	return res
}

// MFAAccount is an account with TOTP enrolled.
type MFAAccount struct {
	Email    string
	Secret   string
	Recovery []string
}

// MFAUser creates an account with TOTP enrolled.
func (w *World) MFAUser(local string) MFAAccount {
	w.T.Helper()
	email := w.FreshEmail(local)
	w.SeedUser(email, false)
	c := w.NewClient()
	c.Login(email, false)
	secret, recovery := c.EnrollTOTP(w)
	return MFAAccount{Email: email, Secret: secret, Recovery: recovery}
}

// Bind returns the browser-binding secret of the ceremony begun by r: the "bind" member of the body
// under the Bearer transport, the bind cookie of the jar under cookies, "" when there is none.
func (c *Client) Bind(r *Resp) string {
	if b := r.Field(egauth.FieldBind); b != "" {
		return b
	}
	if k, ok := c.Cookie("egauth_bind"); ok {
		return k.Value
	}
	return ""
}

// FlowHandle returns the MFA flow handle a login response parked: the "flow" member of the body under
// the Bearer transport, the SameSite=Strict cookie the response set under cookies (the flow cookie is
// the only Strict one, and only internal/cookie may spell its name), "" when there is none.
func (c *Client) FlowHandle(r *Resp) string {
	if h := r.Field(egauth.FieldFlow); h != "" {
		return h
	}
	for _, k := range r.Cookies {
		if k.SameSite == http.SameSiteStrictMode && k.MaxAge > 0 {
			return k.Value
		}
	}
	return ""
}
