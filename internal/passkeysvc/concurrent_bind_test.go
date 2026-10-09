package passkeysvc_test

import (
	"net/http"
	"testing"

	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/routes"
)

type jar map[string]*http.Cookie

func (j jar) absorb(cs []*http.Cookie) {
	for _, c := range cs {
		if c.MaxAge < 0 {
			delete(j, c.Name)
			continue
		}
		j[c.Name] = c
	}
}

func (j jar) cookies() []*http.Cookie {
	out := make([]*http.Cookie, 0, len(j))
	for _, c := range j {
		out = append(out, &http.Cookie{Name: c.Name, Value: c.Value})
	}
	return out
}

func (w *world) browserBegin(j jar, fields map[string]any) challenge {
	w.t.Helper()
	rec := w.do(req{path: routes.PasskeyLoginBegin, fields: fields, cookies: j.cookies()})
	expect(w.t, rec, http.StatusOK)
	j.absorb(rec.Result().Cookies())
	var c challenge
	decodeInto(w.t, rec, &c)
	return c
}

func (w *world) browserFinish(j jar, c challenge, body []byte) *http.Response {
	w.t.Helper()
	rec := w.finishLogin(c, j.cookies(), body)
	j.absorb(rec.Result().Cookies())
	return rec.Result()
}

func TestConcurrentDiscoverableBeginsBothFinish(t *testing.T) {
	w := newWorld(t)
	_, a := w.enrolled("alice@example.com")
	j := jar{}
	c1 := w.browserBegin(j, nil)
	c2 := w.browserBegin(j, nil)
	if res := w.browserFinish(j, c1, a.DiscoverableLogin(t, c1.Options)); res.StatusCode != http.StatusOK {
		t.Fatalf("finish of the first begin: %d", res.StatusCode)
	}
	if res := w.browserFinish(j, c2, a.DiscoverableLogin(t, c2.Options)); res.StatusCode != http.StatusOK {
		t.Fatalf("finish of the second begin: %d", res.StatusCode)
	}
}

func TestAutofillThenUsernameFirstBothFinish(t *testing.T) {
	w := newWorld(t)
	_, a := w.enrolled("alice@example.com")
	j := jar{}
	autofill := w.browserBegin(j, nil)
	button := w.browserBegin(j, map[string]any{routes.FieldIdentifier: "alice@example.com"})
	if res := w.browserFinish(j, autofill, a.DiscoverableLogin(t, autofill.Options)); res.StatusCode != http.StatusOK {
		t.Fatalf("finish of the autofill begin: %d", res.StatusCode)
	}
	if res := w.browserFinish(j, button, a.Login(t, button.Options)); res.StatusCode != http.StatusOK {
		t.Fatalf("finish of the username-first begin: %d", res.StatusCode)
	}
}

func TestLoginFinishKeepsTheBindCookie(t *testing.T) {
	w := newWorld(t)
	_, a := w.enrolled("alice@example.com")
	j := jar{}
	c := w.browserBegin(j, nil)
	res := w.browserFinish(j, c, a.DiscoverableLogin(t, c.Options))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("finish %d", res.StatusCode)
	}
	name := w.cookies.CookieName(cookie.Bind)
	for _, ck := range res.Cookies() {
		if ck.Name == name {
			t.Fatalf("the finish rewrote the bind cookie shared with other ceremonies: %v", ck)
		}
	}
}

func TestMalformedPresentedBindIsNotReused(t *testing.T) {
	w := newWorld(t)
	_, a := w.enrolled("alice@example.com")
	name := w.cookies.CookieName(cookie.Bind)
	for _, weak := range []string{"x", "AAAA", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		j := jar{name: {Name: name, Value: weak}}
		c := w.browserBegin(j, nil)
		if j[name].Value == weak {
			t.Fatalf("a malformed bind %q was reused", weak)
		}
		forged := jar{name: {Name: name, Value: weak}}
		if res := w.browserFinish(forged, c, a.DiscoverableLogin(t, c.Options)); res.StatusCode != http.StatusBadRequest {
			t.Fatalf("finish with the malformed bind %q: %d", weak, res.StatusCode)
		}
		if res := w.browserFinish(j, c, a.DiscoverableLogin(t, c.Options)); res.StatusCode != http.StatusOK {
			t.Fatalf("finish with the minted bind: %d", res.StatusCode)
		}
	}
}

func TestBearerBeginsAlwaysMintDistinctBinds(t *testing.T) {
	w := newWorld(t)
	w.enrolled("alice@example.com")
	j := jar{}
	w.browserBegin(j, nil)
	seen := map[string]bool{}
	for range 3 {
		rec := w.do(req{path: routes.PasskeyLoginBegin, bearer: true, cookies: j.cookies()})
		expect(t, rec, http.StatusOK)
		var c challenge
		decodeInto(t, rec, &c)
		if c.Bind == "" || seen[c.Bind] || c.Bind == j[w.cookies.CookieName(cookie.Bind)].Value {
			t.Fatalf("bearer bind %q is not fresh", c.Bind)
		}
		seen[c.Bind] = true
	}
}
