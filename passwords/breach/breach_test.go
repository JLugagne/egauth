package breach_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/outbound"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/breach"
)

const passwordSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

func TestHIBPIsABreachCheckerThatNeverFetchesOnItsOwn(t *testing.T) {
	var c passwords.BreachChecker = breach.HIBP()
	breached, err := c.IsBreached(context.Background(), "password")
	if !errors.Is(err, breach.ErrUnresolved) || breached {
		t.Fatalf("IsBreached = %v, %v; an unresolved spec fails closed", breached, err)
	}
}

func TestQuerySendsOnlyTheHashPrefix(t *testing.T) {
	q, err := breach.HIBP().Query(context.Background(), "password")
	if err != nil {
		t.Fatal(err)
	}
	req := q.Request()
	if req.Method != http.MethodGet || req.URL.String() != "https://api.pwnedpasswords.com/range/5BAA6" {
		t.Fatalf("request = %s %s", req.Method, req.URL)
	}
	if req.Header.Get("Add-Padding") != "true" || req.Header.Get("User-Agent") == "" {
		t.Fatalf("headers = %v", req.Header)
	}
	if strings.Contains(req.URL.String(), passwordSuffix) {
		t.Fatal("the hash suffix left the process")
	}
}

func TestBreachedMatchesTheSuffix(t *testing.T) {
	q, err := breach.HIBP().Query(context.Background(), "password")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		body string
		want bool
	}{
		{"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n" + passwordSuffix + ":3861493\r\n", true},
		{strings.ToLower(passwordSuffix) + ":2\n", true},
		{passwordSuffix + ":0\n", false},
		{"0018A45C4D1DEF81644B54AB7F969B88D65:1\n", false},
		{"", false},
	}
	for _, c := range cases {
		got, err := q.Breached(response(http.StatusOK, c.body))
		if err != nil || got != c.want {
			t.Errorf("Breached(%q) = %v, %v; want %v", c.body, got, err, c.want)
		}
	}
}

func TestBreachedFailsClosed(t *testing.T) {
	q, err := breach.HIBP().Query(context.Background(), "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Breached(response(http.StatusServiceUnavailable, "")); !errors.Is(err, breach.ErrLookup) {
		t.Fatalf("non-200: %v", err)
	}
	if _, err := q.Breached(response(http.StatusOK, passwordSuffix+":many\n")); !errors.Is(err, breach.ErrLookup) {
		t.Fatalf("malformed count: %v", err)
	}
	huge := strings.Repeat("0018A45C4D1DEF81644B54AB7F969B88D65:1\n", (4<<20)/38+2)
	if _, err := q.Breached(response(http.StatusOK, huge)); !errors.Is(err, breach.ErrLookup) {
		t.Fatalf("oversized body: %v", err)
	}
	if _, err := q.Breached(nil); !errors.Is(err, breach.ErrLookup) {
		t.Fatalf("nil response: %v", err)
	}
}

func TestZeroSpecRefusesToQuery(t *testing.T) {
	if _, err := (breach.Spec{}).Query(context.Background(), "password"); !errors.Is(err, breach.ErrUnresolved) {
		t.Fatalf("zero Spec: %v", err)
	}
}

func TestBreachedRefusesMalformedLines(t *testing.T) {
	q, err := breach.HIBP().Query(context.Background(), "password")
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		"<html>maintenance</html>\n",
		"0018A45C4D1DEF81644B54AB7F969B88D65\n",
		"0018A45C4D1DEF81644B54AB7F969B88D65:x\n",
		"0018A45C:1\n",
		"ZZ18A45C4D1DEF81644B54AB7F969B88D65:1\n",
		"0018A45C4D1DEF81644B54AB7F969B88D65:-1\n",
	} {
		if _, err := q.Breached(response(http.StatusOK, body)); !errors.Is(err, breach.ErrLookup) {
			t.Errorf("Breached(%q) = %v, want ErrLookup", body, err)
		}
	}
	if got, err := q.Breached(response(http.StatusOK, "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\r\n")); err != nil || got {
		t.Fatalf("a trailing blank line is not malformed: %v, %v", got, err)
	}
}

func TestRangeLookupThroughTheOutboundClient(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path+"|"+r.Header.Get("Add-Padding"))
		if r.URL.Path != "/range/5BAA6" {
			_, _ = io.WriteString(w, "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n")
			return
		}
		_, _ = io.WriteString(w, "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n"+passwordSuffix+":3861493\r\n")
	}))
	defer srv.Close()
	allow, err := outbound.NewAllowance([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	if err != nil {
		t.Fatal(err)
	}
	client := outbound.New(outbound.Config{Static: allow}).Static()
	spec := breach.RangeSpecForTest(srv.URL + "/range/")
	lookup := func(pw string) (bool, error) {
		return spec.Lookup(context.Background(), pw, client.DoSecretPath)
	}
	if got, err := lookup("password"); err != nil || !got {
		t.Fatalf("breached password = %v, %v", got, err)
	}
	if got, err := lookup("correct horse battery staple 2026"); err != nil || got {
		t.Fatalf("clean password = %v, %v", got, err)
	}
	if len(seen) != 2 || seen[0] != "/range/5BAA6|true" {
		t.Fatalf("requests = %v", seen)
	}
	for _, s := range seen {
		if strings.Contains(s, passwordSuffix) {
			t.Fatal("the hash suffix left the process")
		}
	}
}

func TestLookupFailsClosed(t *testing.T) {
	spec := breach.HIBP()
	down := func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") }
	if got, err := spec.Lookup(context.Background(), "password", down); got || !errors.Is(err, breach.ErrLookup) {
		t.Fatalf("send error: %v, %v", got, err)
	}
	if got, err := spec.Lookup(context.Background(), "password", nil); got || !errors.Is(err, breach.ErrLookup) {
		t.Fatalf("nil sender: %v, %v", got, err)
	}
	refused := func(*http.Request) (*http.Response, error) { return response(http.StatusTooManyRequests, ""), nil }
	if got, err := spec.Lookup(context.Background(), "password", refused); got || !errors.Is(err, breach.ErrLookup) {
		t.Fatalf("non-200: %v, %v", got, err)
	}
	if _, err := (breach.Spec{}).Lookup(context.Background(), "password", down); !errors.Is(err, breach.ErrUnresolved) {
		t.Fatalf("zero Spec: %v", err)
	}
}
