package codesvc_test

import (
	"context"
	"crypto/sha256"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/codesvc"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

type issuedCode struct {
	handle string
	bind   *http.Cookie
	code   string
}

func (w *world) requestCode(identifier string, d *fakeDelivery) issuedCode {
	w.t.Helper()
	before := len(d.all())
	rec := w.do(req{path: routes.CodeRequest, fields: map[string]string{routes.FieldIdentifier: identifier}})
	if rec.Code != http.StatusOK {
		w.t.Fatalf("code request = %d %s", rec.Code, rec.Body.String())
	}
	msgs := w.waitSent(d, before+1)
	return issuedCode{handle: decode(w.t, rec)["handle"], bind: bindCookie(rec), code: msgs[len(msgs)-1].code}
}

func (w *world) verify(c issuedCode, code string) map[string]string {
	w.t.Helper()
	rec := w.do(req{path: routes.CodeVerify, cookies: []*http.Cookie{c.bind}, fields: map[string]string{routes.FieldHandle: c.handle, routes.FieldCode: code}})
	m := decode(w.t, rec)
	m["status"] = http.StatusText(rec.Code)
	return m
}

func otherCode(c string) string {
	if c == "000000" {
		return "000001"
	}
	return "000000"
}

func TestCodeRequestAnswersAHandleForEveryIdentifier(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	var shapes []string
	for _, id := range []string{"ann@example.com", "nobody@example.com"} {
		rec := w.do(req{path: routes.CodeRequest, fields: map[string]string{routes.FieldIdentifier: id}})
		body := decode(t, rec)
		if rec.Code != http.StatusOK || body["state"] != "code_sent" || bindCookie(rec) == nil {
			t.Fatalf("%s: %d %v", id, rec.Code, body)
		}
		if _, err := ceremonycodec.ParseHandle(body["handle"]); err != nil {
			t.Fatalf("%s: handle %q is not a 256-bit handle", id, body["handle"])
		}
		shapes = append(shapes, strings.Replace(rec.Body.String(), body["handle"], "H", 1))
	}
	if shapes[0] != shapes[1] {
		t.Fatalf("known and unknown bodies differ: %q vs %q (C-46)", shapes[0], shapes[1])
	}
	w.flush()
	if msgs := w.mail.all(); len(msgs) != 1 || msgs[0].to != "ann@example.com" {
		t.Fatalf("messages = %+v", msgs)
	}
}

func TestDecoyHandleNeverVerifies(t *testing.T) {
	w := newWorld(t)
	rec := w.do(req{path: routes.CodeRequest, fields: map[string]string{routes.FieldIdentifier: "nobody@example.com"}})
	h := decode(t, rec)["handle"]
	w.flush()
	for _, code := range []string{"000000", "123456"} {
		rec := w.do(req{path: routes.CodeVerify, cookies: []*http.Cookie{bindCookie(rec)}, fields: map[string]string{routes.FieldHandle: h, routes.FieldCode: code}})
		if rec.Code != http.StatusUnauthorized || decode(t, rec)["error"] != "invalid_code" {
			t.Fatalf("decoy verify = %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestEmailCodeLoginEndsInCompleteWithTheEmailCodeFactor(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	c := w.requestCode("ann@example.com", w.mail)
	if len(c.code) != 6 {
		t.Fatalf("code %q", c.code)
	}
	if got := w.verify(c, c.code); got["state"] != "authenticated" {
		t.Fatalf("verify = %v", got)
	}
	cs := w.issuer.completions()
	if len(cs) != 1 || cs[0].verified.Subject() != sub || !slices.Equal(cs[0].verified.Factors(), []core.Factor{core.FactorEmailCode}) {
		t.Fatalf("completion = %+v (D-08)", cs)
	}
	if s, bound := cs[0].pending.Subject(); !bound || s != sub {
		t.Fatal("the pending is not bound to the code's subject")
	}
	if got := w.verify(c, c.code); got["error"] != "invalid_code" {
		t.Fatalf("second verify = %v", got)
	}
}

func TestSMSCodeLoginYieldsTheSMSFactor(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	w.withPhone(sub, "+33612345678")
	c := w.requestCode("+33 6 12 34 56 78", w.sms)
	if got := w.verify(c, c.code); got["state"] != "authenticated" {
		t.Fatalf("verify = %v", got)
	}
	cs := w.issuer.completions()
	if len(cs) != 1 || !slices.Equal(cs[0].verified.Factors(), []core.Factor{core.FactorSMSCode}) {
		t.Fatalf("completion = %+v", cs)
	}
	if len(w.mail.all()) != 0 {
		t.Fatal("an SMS code went by email")
	}
}

func TestCodeOfAnotherUserNeverVerifiesAndNeverChargesIt(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	w.user("bob@example.com")
	a := w.requestCode("ann@example.com", w.mail)
	b := w.requestCode("bob@example.com", w.mail)
	if a.code == b.code {
		b = w.requestCode("bob@example.com", w.mail)
	}
	if a.code == b.code {
		t.Skip("colliding random codes")
	}
	if got := w.verify(issuedCode{handle: a.handle, bind: a.bind}, b.code); got["error"] != "invalid_code" {
		t.Fatalf("B's code with A's handle = %v; want invalid_code (C-30)", got)
	}
	rec, err := w.ceremonies.Peek(context.Background(), core.TenantID{}, ceremony.EmailCode, handleHash(t, b.handle))
	if err != nil || rec.Attempts() != 0 {
		t.Fatalf("B's record = %v attempts %d; must be untouched", err, rec.Attempts())
	}
	if got := w.verify(b, b.code); got["state"] != "authenticated" {
		t.Fatalf("B's own code = %v", got)
	}
}

func TestTheCodeIsNeverTheKey(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	c := w.requestCode("ann@example.com", w.mail)
	codeHash := sha256.Sum256([]byte(c.code))
	if _, err := w.ceremonies.Peek(context.Background(), core.TenantID{}, ceremony.EmailCode, codeHash[:]); err == nil {
		t.Fatal("the record is reachable by the code's digest")
	}
	if _, err := w.ceremonies.Peek(context.Background(), core.TenantID{}, ceremony.EmailCode, handleHash(t, c.handle)); err != nil {
		t.Fatalf("the record is not keyed by the handle: %v", err)
	}
	if got := w.verify(issuedCode{handle: c.code, bind: c.bind}, c.code); got["error"] != "invalid_code" {
		t.Fatalf("code as handle = %v", got)
	}
}

func TestCodeRecordIsDeletedAtMaxAttempts(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	c := w.requestCode("ann@example.com", w.mail)
	for range ceremony.EmailCode.MaxAttempts() {
		if got := w.verify(c, otherCode(c.code)); got["error"] != "invalid_code" {
			t.Fatalf("wrong code = %v", got)
		}
	}
	if _, err := w.ceremonies.Peek(context.Background(), core.TenantID{}, ceremony.EmailCode, handleHash(t, c.handle)); err == nil {
		t.Fatal("record survives MaxAttempts failures")
	}
	if got := w.verify(c, c.code); got["error"] != "invalid_code" {
		t.Fatalf("right code after exhaustion = %v", got)
	}
}

func TestLastAttemptCanStillSucceed(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	c := w.requestCode("ann@example.com", w.mail)
	for range ceremony.EmailCode.MaxAttempts() - 1 {
		w.verify(c, otherCode(c.code))
	}
	if got := w.verify(c, c.code); got["state"] != "authenticated" {
		t.Fatalf("right code on the last attempt = %v", got)
	}
}

func TestConcurrentGuessesAreBoundedByMaxAttempts(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	c := w.requestCode("ann@example.com", w.mail)
	var ok atomic.Int64
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Go(func() {
			code := otherCode(c.code)
			if i%7 == 0 {
				code = c.code
			}
			if got := w.verify(c, code); got["state"] == "authenticated" {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	if ok.Load() > 1 {
		t.Fatalf("%d concurrent verifications succeeded; a code is single-use", ok.Load())
	}
	if n := w.counted.charged.Load(); n > int64(ceremony.EmailCode.MaxAttempts()) {
		t.Fatalf("%d attempts were charged and compared; the bound is %d", n, ceremony.EmailCode.MaxAttempts())
	}
}

func TestCodeVerifyNeedsTheBind(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	c := w.requestCode("ann@example.com", w.mail)
	rec := w.do(req{path: routes.CodeVerify, fields: map[string]string{routes.FieldHandle: c.handle, routes.FieldCode: c.code}})
	if rec.Code != http.StatusUnauthorized || decode(t, rec)["error"] != "invalid_code" {
		t.Fatalf("verify without bind = %d %s", rec.Code, rec.Body.String())
	}
	r, err := w.ceremonies.Peek(context.Background(), core.TenantID{}, ceremony.EmailCode, handleHash(t, c.handle))
	if err != nil || r.Attempts() != 0 {
		t.Fatalf("an unbound verify charged the record: %v %d", err, r.Attempts())
	}
}

func TestCodeDiesWithASecurityChange(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	c := w.requestCode("ann@example.com", w.mail)
	if _, err := w.raw.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyAdded}); err != nil {
		t.Fatal(err)
	}
	if got := w.verify(c, c.code); got["status"] != http.StatusText(http.StatusUnauthorized) {
		t.Fatalf("verify after an epoch bump = %v (C-17)", got)
	}
}

func TestCodesOnlyReachUsableVerifiedOwners(t *testing.T) {
	w := newWorld(t)
	unverified := w.user("unv@example.com")
	w.accounts.unverified[unverified] = true
	bob := w.user("bob@example.com")
	if _, err := w.raw.Apply(context.Background(), identity.Tombstone{Subject: bob}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"unv@example.com", "+33600000000", "BOB@example.com "} {
		if rec := w.do(req{path: routes.CodeRequest, fields: map[string]string{routes.FieldIdentifier: id}}); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", id, rec.Code)
		}
	}
	w.flush()
	if n := len(w.mail.all()) + len(w.sms.all()); n != 0 {
		t.Fatalf("%d messages sent to ineligible identifiers", n)
	}
}

func TestDisabledChannelIsRefused(t *testing.T) {
	w := newWorld(t, func(c *codesvc.Config) { c.SMSCodes = false; c.Texter = nil })
	rec := w.do(req{path: routes.CodeRequest, fields: map[string]string{routes.FieldIdentifier: "+33612345678"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("SMS code with SMS disabled = %d %s", rec.Code, rec.Body.String())
	}
}

func TestEndpointsFollowTheModules(t *testing.T) {
	w := newWorld(t, func(c *codesvc.Config) { c.MagicLink = false })
	if rec := w.do(req{path: routes.MagicLinkRequest, fields: map[string]string{routes.FieldIdentifier: "a@example.com"}}); rec.Code != http.StatusNotFound {
		t.Fatalf("magic link with the module off = %d", rec.Code)
	}
	if _, err := codesvc.New(codesvc.Config{}); err == nil {
		t.Fatal("zero config accepted")
	}
}

func TestCodeMessageRedactsTheCode(t *testing.T) {
	m := codesvc.CodeMessage{To: "a@example.com", Code: "123456"}
	for _, s := range []string{m.String(), m.GoString(), m.LogValue().String()} {
		if strings.Contains(s, "123456") {
			t.Fatalf("code leaked: %s", s)
		}
	}
}

func handleHash(t *testing.T, h string) []byte {
	t.Helper()
	parsed, err := ceremonycodec.ParseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Hash()
}

func TestConfigRedactsTheDataKey(t *testing.T) {
	c := codesvc.Config{DataKey: []byte("0123456789abcdef0123456789abcdef")}
	for _, s := range []string{c.String(), c.GoString(), c.LogValue().String()} {
		if strings.Contains(s, "0123456789abcdef") {
			t.Fatalf("data key leaked: %s", s)
		}
	}
}

func TestUnboundVerifyIsIndistinguishableFromADecoy(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	known := w.requestCode("ann@example.com", w.mail)
	decoy := w.do(req{path: routes.CodeRequest, fields: map[string]string{routes.FieldIdentifier: "nobody@example.com"}})
	w.flush()
	decoyHandle := decode(t, decoy)["handle"]
	for _, code := range []string{known.code, otherCode(known.code)} {
		a := w.do(req{path: routes.CodeVerify, fields: map[string]string{routes.FieldHandle: known.handle, routes.FieldCode: code}})
		b := w.do(req{path: routes.CodeVerify, fields: map[string]string{routes.FieldHandle: decoyHandle, routes.FieldCode: code}})
		if a.Code != b.Code || a.Body.String() != b.Body.String() {
			t.Fatalf("unbound verify of a real handle = %d %s, of a decoy = %d %s; the requester learns the account exists (C-46)",
				a.Code, a.Body.String(), b.Code, b.Body.String())
		}
	}
}
