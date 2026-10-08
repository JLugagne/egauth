package httpx_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/store/limiter"
)

func capture(t *testing.T, w *world, meta httpx.Meta, r *http.Request) *httpx.Request {
	t.Helper()
	var got *httpx.Request
	h := w.handler(t, meta, func(rw http.ResponseWriter, req *httpx.Request) {
		got = req
		req.Respond(rw, httpx.Response{})
	})
	if resp := serve(h, r); resp.Code != http.StatusOK {
		t.Fatalf("status %d %s", resp.Code, resp.Body)
	}
	return got
}

func TestJSONKeepsOnlyFieldSet(t *testing.T) {
	w := newWorld(t)
	r := capture(t, w, loginMeta(), post(`{"identifier":"a@example.com","password":"pw","remember":true,"code":123456,"return_to":null,"is_admin":true,"nested":{"identifier":"x"},"list":[1]}`, "application/json; charset=utf-8"))
	if r.Field("identifier") != "a@example.com" || r.Field("password") != "pw" || r.Field("code") != "123456" {
		t.Fatalf("fields %q %q %q", r.Field("identifier"), r.Field("password"), r.Field("code"))
	}
	if !r.Flag("remember") || r.Has("return_to") || r.Has("is_admin") || r.Field("is_admin") != "" || r.Has("nested") {
		t.Fatal("unknown or null fields leaked into the request")
	}
	if r.WebAuthnBody() != nil {
		t.Fatal("raw body exposed outside the WebAuthn cap")
	}
	if b, _ := io.ReadAll(r.HTTP().Body); len(b) != 0 {
		t.Fatal("body must be consumed once")
	}
}

func TestFormKeepsOnlyFieldSetAndIgnoresQuery(t *testing.T) {
	w := newWorld(t)
	req := post(`identifier=a%40example.com&remember=on&role=admin`, "application/x-www-form-urlencoded")
	req.URL.RawQuery = "password=from-url&confirm=1"
	r := capture(t, w, loginMeta(), req)
	if r.Field("identifier") != "a@example.com" || !r.Flag("remember") || r.Has("role") {
		t.Fatalf("form fields wrong")
	}
	if r.Has("password") || r.Has("confirm") {
		t.Fatal("an unsafe request must never take fields from the URL")
	}
}

func TestSafeMethodTakesFieldsFromQuery(t *testing.T) {
	w := newWorld(t)
	meta := httpx.Meta{SetsCookies: true, BodyCap: httpx.FormBodyCap, ClientLimit: limiter.LoginClient}
	req := httptest.NewRequest(http.MethodGet, origin+"/auth/oauth/x/begin?return_to=%2Fhome&remember=1&state=s&code=c", strings.NewReader("password=body"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "198.51.100.7:1"
	r := capture(t, w, meta, req)
	if r.Field("return_to") != "/home" || !r.Flag("remember") || r.Field("code") != "c" || r.Has("state") || r.Has("password") {
		t.Fatal("query fields wrong")
	}
	if r.HTTP().URL.Query().Get("state") != "s" {
		t.Fatal("protocol query parameters stay readable on the raw request")
	}
	bad := httptest.NewRequest(http.MethodGet, origin+"/auth/x?code=a&code=b", nil)
	bad.RemoteAddr = "198.51.100.7:1"
	h := w.handler(t, meta, nil)
	if resp := serve(h, bad); resp.Code != http.StatusBadRequest {
		t.Fatalf("repeated query field: %d", resp.Code)
	}
}

func TestEmptyBodyWithoutContentTypeHasNoFields(t *testing.T) {
	w := newWorld(t)
	r := capture(t, w, loginMeta(), post(``, ""))
	if r.Has("identifier") {
		t.Fatal("phantom field")
	}
}

func TestFlagValues(t *testing.T) {
	for v, want := range map[string]bool{"true": true, "TRUE": true, "1": true, "on": true, "yes": true, "false": false, "0": false, "": false, "y": false} {
		r := capture(t, newWorld(t), loginMeta(), post(`confirm=`+v, "application/x-www-form-urlencoded"))
		if r.Flag("confirm") != want {
			t.Errorf("%q: got %v", v, !want)
		}
	}
}

func TestRequestRendersWithoutValues(t *testing.T) {
	w := newWorld(t)
	r := capture(t, w, loginMeta(), post(`{"password":"hunter2-secret","new_password":"newpw-secret","captcha_token":"cap-secret"}`, "application/json"))
	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Info("req", "ptr", r, "val", *r)
	for _, s := range []string{
		fmt.Sprint(r), fmt.Sprintf("%#v", r), fmt.Sprintf("%+v", r), r.LogValue().String(),
		fmt.Sprint(*r), fmt.Sprintf("%#v", *r), fmt.Sprintf("%+v", *r), fmt.Sprintf("%v", []httpx.Request{*r}),
		logged.String(),
	} {
		if strings.Contains(s, "hunter2") || strings.Contains(s, "newpw") || strings.Contains(s, "cap-secret") {
			t.Fatalf("request leaked a field value: %s", s)
		}
	}
}

func TestEndpointCallNeverExposesCaptchaToken(t *testing.T) {
	w := newWorld(t)
	h := w.handler(t, loginMeta(), nil)
	if resp := serve(h, post(`{"captcha_token":"cap-secret"}`, "application/json")); resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	call := w.hook.last
	if call.CaptchaToken() != "cap-secret" {
		t.Fatalf("the hook must read the captcha token, got %q", call.CaptchaToken())
	}
	j, err := json.Marshal(call)
	if err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("call", "call", call)
	for _, s := range []string{fmt.Sprint(call), fmt.Sprintf("%#v", call), fmt.Sprintf("%+v", call), call.LogValue().String(), string(j), logged.String()} {
		if strings.Contains(s, "cap-secret") {
			t.Fatalf("captcha token leaked: %s", s)
		}
	}
}

func origins(t *testing.T) redirect.Origins {
	t.Helper()
	o, err := redirect.NewOrigins(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func pendingWith(tr core.Transport) core.Pending {
	return core.ForTestPending(core.ForTestPendingFields{Subject: subject(acme), Transport: tr, ExpiresAt: start.Add(time.Hour)})
}

func TestRespondMatrix(t *testing.T) {
	home, err := redirect.Parse("/home", origins(t))
	if err != nil {
		t.Fatal(err)
	}
	form, ct := "a=1", "application/x-www-form-urlencoded"
	cases := []struct {
		name      string
		body, ct  string
		header    string
		pending   *core.Pending
		resp      httpx.Response
		status    int
		location  string
		jsonReply bool
	}{
		{"sealed cookies, form, location: 303", form, ct, "", new(pendingWith(core.TransportCookies)), httpx.Response{Location: home}, 303, "/home", false},
		{"sealed cookies, json request: JSON", "{}", "application/json", "", new(pendingWith(core.TransportCookies)), httpx.Response{Location: home}, 200, "", true},
		{"sealed bearer, form: JSON", form, ct, "", new(pendingWith(core.TransportBearer)), httpx.Response{Location: home}, 200, "", true},
		{"sealed cookies wins over a bearer header", form, ct, "bearer", new(pendingWith(core.TransportCookies)), httpx.Response{Location: home}, 303, "/home", false},
		{"sealed cookies, no location: JSON", form, ct, "", new(pendingWith(core.TransportCookies)), httpx.Response{Status: 202}, 202, "", true},
		{"zero pending: JSON", form, ct, "", new(core.Pending{}), httpx.Response{Location: home}, 200, "", true},
		{"no session, no pending: JSON even on a cookies request", form, ct, "", nil, httpx.Response{Location: home}, 200, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			h := w.handler(t, loginMeta(), func(rw http.ResponseWriter, r *httpx.Request) {
				if tc.pending != nil {
					r.RespondPending(rw, *tc.pending, tc.resp)
					return
				}
				r.Respond(rw, tc.resp)
			})
			req := post(tc.body, tc.ct)
			if tc.header != "" {
				req.Header.Set("X-Egauth-Transport", tc.header)
			}
			resp := serve(h, req)
			if resp.Code != tc.status || resp.Header().Get("Location") != tc.location {
				t.Fatalf("status %d location %q", resp.Code, resp.Header().Get("Location"))
			}
			if tc.jsonReply && (resp.Header().Get("Content-Type") != "application/json" || strings.TrimSpace(resp.Body.String()) != "{}") {
				t.Fatalf("json reply %q %q", resp.Header().Get("Content-Type"), resp.Body)
			}
			if resp.Header().Get("Cache-Control") != "no-store" || resp.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("security headers missing")
			}
		})
	}
}

func TestRespondFollowsTheResumedSessionTransport(t *testing.T) {
	home, err := redirect.Parse("/home", origins(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		transport core.Transport
		header    string
		status    int
	}{
		"cookies session, bearer header": {core.TransportCookies, "bearer", http.StatusSeeOther},
		"bearer session, no header":      {core.TransportBearer, "", http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.auth.attrs = attrs(core.ForTestAttrs{Subject: subject(acme), Factors: []core.Factor{core.FactorPassword}, PrimaryAt: start, Transport: tc.transport})
			meta := sensitiveMeta()
			meta.Sensitive = false
			h := w.handler(t, meta, func(rw http.ResponseWriter, r *httpx.Request) { r.Respond(rw, httpx.Response{Location: home}) })
			req := post("a=1", "application/x-www-form-urlencoded")
			req.Header.Set("Cookie", "__Host-session=x")
			if tc.header != "" {
				req.Header.Set("X-Egauth-Transport", tc.header)
			}
			if resp := serve(h, req); resp.Code != tc.status {
				t.Fatalf("status %d %s", resp.Code, resp.Body)
			}
		})
	}
}

func TestFailNeverLeaksErrorText(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{errors.Join(httpx.NewProblem(http.StatusConflict, "email_taken"), errors.New("pq: secret detail")), 409, "email_taken"},
		{errors.New("pq: secret detail"), 500, "internal_error"},
		{nil, 500, "internal_error"},
	}
	for _, tc := range cases {
		w := newWorld(t)
		h := w.handler(t, loginMeta(), func(rw http.ResponseWriter, r *httpx.Request) { r.Fail(rw, tc.err) })
		resp := serve(h, post(`{}`, "application/json"))
		if resp.Code != tc.status || errorCode(t, resp) != tc.code || strings.Contains(resp.Body.String(), "secret") {
			t.Fatalf("%v: %d %s", tc.err, resp.Code, resp.Body)
		}
	}
}

func TestUnencodableBodyAnswers500(t *testing.T) {
	w := newWorld(t)
	h := w.handler(t, loginMeta(), func(rw http.ResponseWriter, r *httpx.Request) {
		r.Respond(rw, httpx.Response{Body: map[string]any{"f": func() {}}})
	})
	if resp := serve(h, post(`{}`, "application/json")); resp.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", resp.Code)
	}
}
