package journeytest

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/webauthntest"
)

func secondDrivers() []SecondDriver {
	return []SecondDriver{
		{
			MFA: MFATOTP, Module: "MFA", Factor: "totp", Verified: event.MFAVerified,
			Enroll: enrollTOTP, Complete: completeTOTP,
		},
		{
			MFA: MFARecoveryCode, Module: "MFA", Factor: "rc", Verified: event.MFAVerified,
			Enroll: enrollRecovery, Complete: completeRecovery,
		},
		{
			MFA: MFAPasskeyStepUp, Module: "Passkey", Factor: "pk_stepup", Verified: event.MFAVerified,
			Enroll: enrollStepUpPasskey, Complete: completeStepUpPasskey,
		},
	}
}

func supportDrivers() []ModuleDriver {
	return []ModuleDriver{
		{Module: "Verification", Support: "email and phone verification with the session of the cell", Check: checkVerification},
		{Module: "SelfDelete", Support: "account deletion with the session of the cell", Check: checkSelfDelete, Terminal: true},
		{
			Module: "APIKeys", Support: "credential-kind separation: a session never authenticates ProtectAPI",
			Check: func(r *Run, c *Client) {
				r.T.Helper()
				if res := c.Do(Req{Path: APIRoute}); res.Status != http.StatusUnauthorized {
					r.T.Fatalf("journeytest: a session credential on %s answered %d, want 401", APIRoute, res.Status)
				}
			},
		},
	}
}

func checkVerification(r *Run, c *Client) {
	r.T.Helper()
	w := r.World
	if res := r.post(c, egauth.PathEmailVerifyRequest, map[string]any{}); res.Status != http.StatusAccepted {
		r.T.Fatalf("journeytest: email verification request with the cell session answered %s, want 202", Describe(res))
	}
	n := w.TextCount("PhoneVerificationCode")
	begin := r.post(c, egauth.PathPhoneVerifyRequest, map[string]any{egauth.FieldPhone: verificationPhone})
	r.expect(begin, http.StatusOK, "phone verification request with the cell session")
	w.WaitText("PhoneVerificationCode", n+1)
	wrong := r.post(c, egauth.PathPhoneVerify, map[string]any{egauth.FieldHandle: begin.Field(egauth.FieldHandle), egauth.FieldCode: "000000"})
	if wrong.Status != http.StatusBadRequest {
		r.T.Fatalf("journeytest: a wrong phone verification code answered %s, want 400, a refusal that keeps the session", Describe(wrong))
	}
	r.expect(c.Session(), http.StatusOK, "GET /session after a refused phone verification")
}

func checkSelfDelete(r *Run, c *Client) {
	r.T.Helper()
	w := r.World
	mark := w.Events.Mark()
	r.expect(r.post(c, egauth.PathAccountDelete, map[string]any{}), http.StatusOK, "account deletion")
	r.settle()
	if !slices.Contains(w.Events.Since(mark), event.AccountDeleted) {
		r.T.Fatalf("journeytest: account deletion emitted %v, want %s among them", w.Events.Since(mark), event.AccountDeleted)
	}
	if got := c.Session(); got.Status != http.StatusUnauthorized {
		r.T.Fatalf("journeytest: GET /session of a deleted account answered %d, want 401", got.Status)
	}
	seen := w.Seen.Count()
	if got := c.Do(Req{Path: ProtectRoute}); got.Status != http.StatusUnauthorized || w.Seen.Count() != seen {
		r.T.Fatalf("journeytest: a Protect route served a deleted account: %s", Describe(got))
	}
}

func enrollTOTP(r *Run, c *Client) {
	r.T.Helper()
	r.Secret, r.Recovery = c.EnrollTOTP(r.World)
	if len(r.Recovery) == 0 {
		r.T.Fatal("journeytest: TOTP confirmation returned no recovery codes")
	}
}

func enrollRecovery(r *Run, c *Client) {
	r.T.Helper()
	enrollTOTP(r, c)
	d, _ := primaryDriverOf(r.Cell.Primary)
	if !d.SelfSufficient {
		return
	}
	fresh := r.World.NewClient()
	r.established(d.Login(r, fresh), "sign-in before regenerating the recovery codes")
	res := r.post(fresh, egauth.PathMFARecoveryCodesRegenerate, map[string]any{})
	r.expect(res, http.StatusOK, "recovery codes regeneration")
	var body struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(res.Body, &body); err != nil || len(body.RecoveryCodes) == 0 {
		r.T.Fatalf("journeytest: recovery code regeneration returned no codes: %s", Describe(res))
	}
	r.Recovery = body.RecoveryCodes
}

func completeTOTP(r *Run, c *Client) *Resp {
	r.T.Helper()
	return c.ChallengeTOTP(r.World, r.Secret)
}

func completeRecovery(r *Run, c *Client) *Resp {
	r.T.Helper()
	f := map[string]any{egauth.FieldFactor: "recovery_code", egauth.FieldCode: r.Recovery[0]}
	if c.flow != "" {
		f[egauth.FieldFlow] = c.flow
	}
	return r.post(c, egauth.PathMFAChallenge, f)
}

func enrollStepUpPasskey(r *Run, c *Client) {
	r.T.Helper()
	r.StepUp = webauthntest.New(r.World.Origin)
	r.registerPasskey(c, r.StepUp)
}

func completeStepUpPasskey(r *Run, c *Client) *Resp {
	r.T.Helper()
	f := map[string]any{}
	if c.flow != "" {
		f[egauth.FieldFlow] = c.flow
	}
	begin := r.post(c, egauth.PathMFAPasskeyBegin, f)
	r.expect(begin, http.StatusOK, "passkey step-up begin")
	b := decodeOptions(r.T, begin)
	extra := map[string]any{egauth.FieldHandle: b.Handle}
	if c.flow != "" {
		extra[egauth.FieldFlow] = c.flow
	}
	return r.post(c, egauth.PathMFAPasskeyFinish, mergeJSON(r.T, r.StepUp.Login(r.T, b.Options), extra))
}
