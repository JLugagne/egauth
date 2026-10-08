package csrf_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
)

const public = "https://app.example.com"

type hdr struct{ k, v string }

func req(method string, h ...hdr) *http.Request {
	r := httptest.NewRequest(method, public+"/auth/login", nil)
	for _, x := range h {
		r.Header.Add(x.k, x.v)
	}
	return r
}

var (
	withCookie     = hdr{"Cookie", "__Host-session=x"}
	sameOrigin     = hdr{"Sec-Fetch-Site", "same-origin"}
	noneSite       = hdr{"Sec-Fetch-Site", "none"}
	sameSite       = hdr{"Sec-Fetch-Site", "same-site"}
	crossSite      = hdr{"Sec-Fetch-Site", "cross-site"}
	goodOrigin     = hdr{"Origin", public}
	extraOrigin    = hdr{"Origin", "https://admin.example.com"}
	badOrigin      = hdr{"Origin", "https://evil.example"}
	nullOrigin     = hdr{"Origin", "null"}
	goodReferer    = hdr{"Referer", public + "/login?x=1"}
	badReferer     = hdr{"Referer", "https://evil.example/" + public}
	bearerHeader   = hdr{"X-Egauth-Transport", "bearer"}
	authorization  = hdr{"Authorization", "Bearer abc.def"}
	navigate       = hdr{"Sec-Fetch-Mode", "navigate"}
	corsMode       = hdr{"Sec-Fetch-Mode", "cors"}
	noCorsMode     = hdr{"Sec-Fetch-Mode", "no-cors"}
	upperOrigin    = hdr{"Origin", "HTTPS://APP.EXAMPLE.COM"}
	portOrigin     = hdr{"Origin", "https://app.example.com:443"}
	userRefererURL = hdr{"Referer", "https://user@app.example.com/x"}
)

func policy(sets, authed bool) csrf.Policy {
	o, err := csrf.NewOrigins(public, []string{"https://admin.example.com"})
	if err != nil {
		panic(err)
	}
	return csrf.Policy{Origins: o.For(core.TenantID{}), SetsCookies: sets, Authenticated: authed, BearerTransport: true}
}

func TestBearerExemptionNeedsBearerTransport(t *testing.T) {
	p := policy(true, false)
	p.BearerTransport = false
	for name, h := range map[string][]hdr{
		"bearer header":        {bearerHeader, crossSite, badOrigin},
		"authorization bearer": {authorization, badOrigin},
		"both":                 {bearerHeader, authorization},
	} {
		t.Run(name, func(t *testing.T) {
			if err := csrf.Check(req(http.MethodPost, h...), p); !errors.Is(err, csrf.ErrForbidden) {
				t.Fatalf("want ErrForbidden, got %v", err)
			}
		})
	}
	if err := csrf.Check(req(http.MethodPost, authorization, badOrigin), csrf.Policy{BearerTransport: false}); err != nil {
		t.Fatalf("an endpoint that sets no cookie stays unchecked without cookies: %v", err)
	}
}

func TestUnsafeMethodDecisionRows(t *testing.T) {
	cases := []struct {
		name  string
		sets  bool
		h     []hdr
		allow bool
	}{
		{"no cookie, endpoint sets no cookie: unchecked", false, []hdr{badOrigin}, true},
		{"no cookie, sets cookies: checked and passes", true, []hdr{sameOrigin, goodOrigin}, true},
		{"no cookie, sets cookies: login CSRF denied", true, []hdr{crossSite, badOrigin}, false},
		{"no cookie, sets cookies, nothing at all: denied", true, nil, false},
		{"cookie: same-origin + origin", false, []hdr{withCookie, sameOrigin, goodOrigin}, true},
		{"cookie: none + origin", false, []hdr{withCookie, noneSite, goodOrigin}, true},
		{"cookie: same-site denied", false, []hdr{withCookie, sameSite, goodOrigin}, false},
		{"cookie: cross-site denied", false, []hdr{withCookie, crossSite, goodOrigin}, false},
		{"cookie: unknown fetch-site denied", false, []hdr{withCookie, {"Sec-Fetch-Site", "weird"}, goodOrigin}, false},
		{"cookie: duplicate fetch-site denied", false, []hdr{withCookie, sameOrigin, sameOrigin, goodOrigin}, false},
		{"cookie: no fetch metadata, origin matches", false, []hdr{withCookie, goodOrigin}, true},
		{"cookie: extra origin matches", false, []hdr{withCookie, extraOrigin}, true},
		{"cookie: origin mismatch", false, []hdr{withCookie, sameOrigin, badOrigin}, false},
		{"cookie: origin null", false, []hdr{withCookie, sameOrigin, nullOrigin}, false},
		{"cookie: origin case-insensitive scheme and host", false, []hdr{withCookie, upperOrigin}, true},
		{"cookie: explicit default port is not the origin", false, []hdr{withCookie, portOrigin}, false},
		{"cookie: duplicate origin denied", false, []hdr{withCookie, goodOrigin, goodOrigin}, false},
		{"cookie: no origin, referer matches", false, []hdr{withCookie, sameOrigin, goodReferer}, true},
		{"cookie: no origin, referer mismatch", false, []hdr{withCookie, badReferer}, false},
		{"cookie: no origin, referer with userinfo", false, []hdr{withCookie, userRefererURL}, false},
		{"cookie: no origin, no referer", false, []hdr{withCookie, sameOrigin}, false},
		{"cookie: origin present wins over referer", false, []hdr{withCookie, badOrigin, goodReferer}, false},
		{"bearer header, no cookie: exempt", true, []hdr{bearerHeader, crossSite, badOrigin}, true},
		{"authorization bearer, no cookie: exempt", true, []hdr{authorization, crossSite}, true},
		{"bearer header with cookie: not exempt", true, []hdr{withCookie, bearerHeader, crossSite}, false},
		{"authorization with cookie: not exempt", false, []hdr{withCookie, authorization, badOrigin}, false},
		{"other transport header value: not exempt", true, []hdr{{"X-Egauth-Transport", "cookies"}}, false},
		{"basic authorization: not exempt", true, []hdr{{"Authorization", "Basic abc"}}, false},
		{"empty bearer token: not exempt", true, []hdr{{"Authorization", "Bearer "}}, false},
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, "PROPFIND"} {
		for _, tc := range cases {
			t.Run(m+" "+tc.name, func(t *testing.T) {
				err := csrf.Check(req(m, tc.h...), policy(tc.sets, false))
				if tc.allow && err != nil {
					t.Fatalf("want allow, got %v", err)
				}
				if !tc.allow && !errors.Is(err, csrf.ErrForbidden) {
					t.Fatalf("want ErrForbidden, got %v", err)
				}
			})
		}
	}
}

func TestSafeMethodDecisionRows(t *testing.T) {
	cases := []struct {
		name   string
		authed bool
		h      []hdr
		allow  bool
	}{
		{"cross-site cors fetch with cookie on protected route", true, []hdr{withCookie, crossSite, corsMode}, false},
		{"cross-site no-cors with cookie on protected route", true, []hdr{withCookie, crossSite, noCorsMode}, false},
		{"cross-site without mode with cookie on protected route", true, []hdr{withCookie, crossSite}, false},
		{"cross-site navigation with cookie on protected route", true, []hdr{withCookie, crossSite, navigate}, true},
		{"same-site fetch with cookie on protected route", true, []hdr{withCookie, sameSite, corsMode}, true},
		{"cross-site fetch without cookie", true, []hdr{crossSite, corsMode}, true},
		{"cross-site fetch with cookie on public endpoint", false, []hdr{withCookie, crossSite, corsMode}, true},
		{"no fetch metadata with cookie", true, []hdr{withCookie, badOrigin}, true},
		{"duplicate fetch-site with cookie on protected route", true, []hdr{withCookie, crossSite, sameOrigin, navigate}, false},
	}
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		for _, tc := range cases {
			t.Run(m+" "+tc.name, func(t *testing.T) {
				err := csrf.Check(req(m, tc.h...), policy(true, tc.authed))
				if tc.allow && err != nil {
					t.Fatalf("want allow, got %v", err)
				}
				if !tc.allow && !errors.Is(err, csrf.ErrForbidden) {
					t.Fatalf("want ErrForbidden, got %v", err)
				}
			})
		}
	}
}

func TestZeroPolicyDeniesCheckedRequests(t *testing.T) {
	if err := csrf.Check(req(http.MethodPost, withCookie, goodOrigin), csrf.Policy{}); !errors.Is(err, csrf.ErrForbidden) {
		t.Fatalf("zero policy must deny, got %v", err)
	}
}

func TestOriginsTenantExpansion(t *testing.T) {
	o, err := csrf.NewOrigins("https://{tenant}.Example.com", []string{"https://extra.example.org:8443"})
	if err != nil {
		t.Fatal(err)
	}
	acme, err := core.ParseTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	got := o.For(acme)
	want := []string{"https://acme.example.com", "https://extra.example.org:8443"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
	if got := o.For(core.TenantID{}); !slices.Equal(got, []string{"https://extra.example.org:8443"}) {
		t.Fatalf("zero tenant must not expand the template: %v", got)
	}
	r := req(http.MethodPost, withCookie, hdr{"Origin", "https://acme.example.com"})
	if err := csrf.Check(r, csrf.Policy{Origins: got}); err != nil {
		t.Fatalf("tenant origin refused: %v", err)
	}
	other := req(http.MethodPost, withCookie, hdr{"Origin", "https://evil.example.com"})
	if err := csrf.Check(other, csrf.Policy{Origins: got}); !errors.Is(err, csrf.ErrForbidden) {
		t.Fatalf("other tenant's origin accepted: %v", err)
	}
}

func TestNewOriginsValidation(t *testing.T) {
	bad := []struct {
		public string
		extra  []string
	}{
		{"", nil},
		{"app.example.com", nil},
		{"ftp://app.example.com", nil},
		{"https://app.example.com/path", nil},
		{"https://user@app.example.com", nil},
		{"https://app.example.com?q", nil},
		{"https://app.{tenant}.com", nil},
		{"https://app.example.com", []string{"https://{tenant}.example.com"}},
		{"https://app.example.com", []string{"null"}},
		{"https://app.example.com", []string{""}},
	}
	for _, tc := range bad {
		if _, err := csrf.NewOrigins(tc.public, tc.extra); !errors.Is(err, csrf.ErrInvalidOrigin) {
			t.Errorf("%q %q: want ErrInvalidOrigin, got %v", tc.public, tc.extra, err)
		}
	}
	o, err := csrf.NewOrigins("https://App.Example.com:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := o.For(core.TenantID{}); !slices.Equal(got, []string{"https://app.example.com"}) {
		t.Fatalf("canonical origin %v", got)
	}
}

func TestBearerAuthorization(t *testing.T) {
	for name, tc := range map[string]struct {
		h    []hdr
		want bool
	}{
		"bearer":            {[]hdr{authorization}, true},
		"lowercase scheme":  {[]hdr{{"Authorization", "bearer abc"}}, true},
		"empty credential":  {[]hdr{{"Authorization", "Bearer "}}, false},
		"basic":             {[]hdr{{"Authorization", "Basic eDp5"}}, false},
		"duplicate":         {[]hdr{authorization, authorization}, false},
		"absent":            {nil, false},
		"transport header":  {[]hdr{bearerHeader}, false},
		"scheme without sp": {[]hdr{{"Authorization", "Bearer"}}, false},
	} {
		if got := csrf.BearerAuthorization(req(http.MethodPost, tc.h...)); got != tc.want {
			t.Errorf("%s: got %v want %v", name, got, tc.want)
		}
	}
}
