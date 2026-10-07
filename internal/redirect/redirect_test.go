package redirect_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/redirect"
)

const public = "https://app.example.com"

func testOrigins(t testing.TB) redirect.Origins {
	t.Helper()
	o, err := redirect.NewOrigins(public, []string{"https://partner.example.com", "http://localhost:8080"})
	require.NoError(t, err)
	return o
}

func TestBypassCorpus(t *testing.T) {
	o := testOrigins(t)
	corpus := []string{
		`/\evil.com`,
		`/%5Cevil.com`,
		`/%5cevil.com`,
		"/\t/evil.com",
		"/\n/evil.com",
		"/\r/evil.com",
		`/%09/evil.com`,
		`/%0a/evil.com`,
		`/%0D/evil.com`,
		`//evil.com`,
		`///evil.com`,
		`//evil.com/path`,
		`/%2F%2Fevil.com`,
		`/%2f%2fevil.com`,
		`/%2F/evil.com`,
		`/%252F%252Fevil.com`,
		`/%25%32%66evil.com`,
		`https:evil.com`,
		`https:/evil.com`,
		`https:///evil.com`,
		`/.//evil.com`,
		`/..//evil.com`,
		`/a/../..//evil.com`,
		`/./%2e/evil.com`,
		`/%2e%2e//evil.com`,
		`/%2E%2E//evil.com`,
		`/a/./b`,
		`/a/b/../c`,
		`/a/..`,
		`/.`,
		`\\evil.com`,
		`\/evil.com`,
		`/\/evil.com`,
		`https://evil.com`,
		`http://evil.com/`,
		`HTTPS://EVIL.COM/`,
		`https://app.example.com.evil.com/`,
		`https://partner.example.com.evil.com/`,
		`https://app.example.com@evil.com/`,
		`https://partner.example.com@evil.com/`,
		`https://user:pass@partner.example.com/`,
		`https://@partner.example.com/`,
		`https://evil.com#@partner.example.com`,
		`/path#fragment`,
		`/path#`,
		`javascript:alert(1)`,
		`JavaScript:alert(1)`,
		`javascript://%0aalert(1)`,
		`data:text/html,<script>alert(1)</script>`,
		`vbscript:msgbox(1)`,
		`/%0d%0aSet-Cookie:%20x=y`,
		`/%00evil`,
		"/\x00evil",
		"/\x7fevil",
		"/\x1bevil",
		` /evil`,
		`/evil `,
		`/ev il`,
		"/　evil",
		"/ evil",
		"/／／evil.com",
		"/∕∕evil.com",
		`evil.com`,
		`evil`,
		`./evil`,
		`../evil`,
		`?next=/`,
		`#top`,
		`ftp://partner.example.com/`,
		`http://partner.example.com/`,
		`https://partner.example.com:8443/`,
		`https://app.example.com/dashboard`,
		`mailto:a@example.com`,
		`/%zz`,
		`/%`,
		`/` + strings.Repeat("a", 600),
	}
	for _, raw := range corpus {
		t.Run(url.PathEscape(raw), func(t *testing.T) {
			tgt, err := redirect.Parse(raw, o)
			require.Error(t, err, "accepted %q as %q", raw, tgt.String())
			require.True(t, tgt.IsZero())
		})
	}
}

func TestParseAccepts(t *testing.T) {
	o := testOrigins(t)
	cases := []struct {
		raw  string
		want string
	}{
		{"/", "/"},
		{"/dashboard", "/dashboard"},
		{"/a/b/c?x=1&y=2", "/a/b/c?x=1&y=2"},
		{"/search?q=a%20b", "/search?q=a%20b"},
		{"/path?", "/path"},
		{"/a//b", "/a//b"},
		{"/next?to=https://evil.com", "/next?to=https://evil.com"},
		{"https://partner.example.com", "https://partner.example.com"},
		{"https://partner.example.com/x?y=z", "https://partner.example.com/x?y=z"},
		{"HTTPS://Partner.Example.com/x", "https://partner.example.com/x"},
		{"http://localhost:8080/cb", "http://localhost:8080/cb"},
	}
	for _, c := range cases {
		t.Run(url.PathEscape(c.raw), func(t *testing.T) {
			tgt, err := redirect.Parse(c.raw, o)
			require.NoError(t, err)
			require.Equal(t, c.want, tgt.String())
			require.False(t, tgt.IsZero())
		})
	}
}

func TestParseEmptyIsNoTarget(t *testing.T) {
	tgt, err := redirect.Parse("", testOrigins(t))
	require.NoError(t, err)
	require.True(t, tgt.IsZero())
	require.Equal(t, "", tgt.String())
}

func TestParseRequiresOrigins(t *testing.T) {
	_, err := redirect.Parse("/x", redirect.Origins{})
	require.ErrorIs(t, err, redirect.ErrNoOrigins)
}

func TestNewOriginsRejectsNonOrigins(t *testing.T) {
	bad := []string{
		"",
		"app.example.com",
		"https://",
		"https://app.example.com/",
		"https://app.example.com/path",
		"https://app.example.com?x",
		"https://app.example.com#x",
		"https://u@app.example.com",
		"ftp://app.example.com",
		"https://app.example.com\\",
		"https://app .example.com",
	}
	for _, b := range bad {
		_, err := redirect.NewOrigins(b, nil)
		require.Error(t, err, "public %q", b)
		_, err = redirect.NewOrigins(public, []string{b})
		require.Error(t, err, "extra %q", b)
	}
}

func FuzzParse(f *testing.F) {
	seeds := []string{
		"/", "/a?b=c", `/\evil`, `/%5Cevil`, "/\t/evil", "//evil", `/%2F%2Fevil`, "https:evil",
		"/.//evil", "https://partner.example.com/x", "https://evil.com", "/%2e%2e//evil", "/a/../b",
		"http://localhost:8080/", "/x#y", "/%252f",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	o := testOrigins(f)
	base, err := url.Parse(public)
	require.NoError(f, err)
	f.Fuzz(func(t *testing.T, raw string) {
		tgt, err := redirect.Parse(raw, o)
		if err != nil {
			if !tgt.IsZero() {
				t.Fatalf("error with non-zero target for %q", raw)
			}
			return
		}
		out := tgt.String()
		if raw == "" {
			if out != "" {
				t.Fatalf("empty input produced %q", out)
			}
			return
		}
		for i := 0; i < len(out); i++ {
			c := out[i]
			if c <= 0x20 || c >= 0x7f || c == '\\' || c == '#' {
				t.Fatalf("output %q of %q contains byte %#x", out, raw, c)
			}
		}
		lower := strings.ToLower(out)
		for _, bad := range []string{"%2f", "%5c", "%09", "%0a", "%0d", "%25", "%2e"} {
			if strings.Contains(lower, bad) {
				t.Fatalf("output %q of %q contains %s", out, raw, bad)
			}
		}
		again, err := redirect.Parse(out, o)
		if err != nil || again.String() != out {
			t.Fatalf("not idempotent: %q -> %q -> %q (%v)", raw, out, again.String(), err)
		}
		u, err := url.Parse(out)
		if err != nil {
			t.Fatalf("output %q of %q does not parse: %v", out, raw, err)
		}
		if u.User != nil || u.Opaque != "" || u.Fragment != "" {
			t.Fatalf("output %q of %q has user, opaque or fragment", out, raw)
		}
		if u.Scheme == "" {
			if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") {
				t.Fatalf("relative output %q of %q is not path-absolute", out, raw)
			}
			r := base.ResolveReference(u)
			if r.Scheme != base.Scheme || r.Host != base.Host {
				t.Fatalf("relative output %q of %q leaves the origin: %s", out, raw, r)
			}
			return
		}
		origin := u.Scheme + "://" + u.Host
		if origin != "https://partner.example.com" && origin != "http://localhost:8080" {
			t.Fatalf("absolute output %q of %q has untrusted origin %q", out, raw, origin)
		}
	})
}
