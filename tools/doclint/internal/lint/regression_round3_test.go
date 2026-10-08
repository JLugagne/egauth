package lint_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/doclint/internal/lint"
)

func TestUnknownQualifierWithCommonMemberNameFails(t *testing.T) {
	for _, b := range []string{"`ghostpkg.Start`", "`ghostpkg.Close()`", "`deletedpkg.ServeHTTP`", "`oldsession.Addr`", "`oldsession.Revoke`", "`r.URL.Nope`", "`s.Addr.Nope`"} {
		if fs := scan(t, b+"\n"); !onlyRule(fs, lint.RuleSymbol, 1) {
			t.Errorf("%q: %v", b, fs)
		}
	}
	if fs := scan(t, "`r.Host` `ctx.Err()` `r.URL.Path` `s.Start()` `s.Addr` `srv.Addr` `w.Header()` `t.Run`\n"); len(fs) != 0 {
		t.Fatalf("variables declared in the loaded modules: %v", fs)
	}
}

func TestBurdenHiddenByHTMLCommentOrHardBreakFails(t *testing.T) {
	for _, md := range []string{
		"Remember <!-- x --> to rotate.\n",
		"Remember<!---->to rotate.\n",
		"Remember<!-->to rotate.\n",
		"Remem<!-- -->ber to rotate.\n",
		"Remember <!-- multi\nline --> to rotate.\n",
		"Remember\\\nto rotate.\n",
		"<!-- remember to rotate -->\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleBurden, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
	for _, md := range []string{
		"Signatures <!-- --> verified against source.\n",
		"Signatures<!---->verified against source.\n",
		"Signatures\\\nverified against source.\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleBanned, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestSymbolReferenceInsideExpressionsResolves(t *testing.T) {
	for _, b := range []string{
		"`alpha.Missing,`", "`alpha.Missing.`", "`alpha.Missing = 1`", "`x := alpha.Missing()`",
		"`alpha.Server.Addr.Nope`", "`f(alpha.Missing)`", "`...alpha.Nope`", "`alpha.New(), alpha.Missing`",
	} {
		if fs := scan(t, b+"\n"); !onlyRule(fs, lint.RuleSymbol, 1) {
			t.Errorf("%q: %v", b, fs)
		}
	}
	good := "`x := alpha.New()` `alpha.Server.Addr,` `alpha.Config.Origin = \"x\"` `f(alpha.Mode)` `doclint:enforced-by <pkg.TestOrSuite>` `internal/core.Thing` `https://example.com/v1.Foo`\n"
	if fs := scan(t, good); len(fs) != 0 {
		t.Fatalf("good expressions: %v", fs)
	}
}

func TestEscapeExcusesOnlyItsOwnSentence(t *testing.T) {
	fs := scan(t, "Remember to rotate. You must also set X. doclint:enforced-by alpha.TestEnforced\n")
	if !onlyRule(fs, lint.RuleBurden, 1) || fs[0].Message == "" {
		t.Fatalf("only the sentence the escape ends may be excused: %v", fs)
	}
	fs = scan(t, "Remember to rotate. doclint:enforced-by alpha.TestEnforced You must also set X.\n")
	if !onlyRule(fs, lint.RuleBurden, 1) {
		t.Fatalf("an escape must not excuse the sentence after it: %v", fs)
	}
	for _, md := range []string{
		"Remember to rotate.\n<!-- doclint:enforced-by alpha.TestEnforced -->\n",
		"Remember to rotate. <!-- doclint:enforced-by alpha.TestEnforced -->\n",
		"Note doclint:enforced-by alpha.TestEnforced you must also set X.\n",
	} {
		if fs := scan(t, md); len(fs) != 0 {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestGoSourceOutsideGoFencesNeedsMarker(t *testing.T) {
	for _, md := range []string{
		"```text\npackage main\n\nfunc main() {}\n```\n",
		"```txt\nfunc Run() {}\n```\n",
		"```text\nx := alpha.New()\n```\n",
		"<pre><code class=\"language-go\">x := 1\n</code></pre>\n",
		"<pre lang=\"go\">\nfoo()\n</pre>\n",
		"<pre>\nfunc main() {}\n</pre>\n",
		"Intro.\n\n<PRE><code>\ns := alpha.New()\ns.Start()\n</code></PRE>\n",
		"See <code class=\"lang-go\">x := 1</code>.\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleEmbed, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
	for _, md := range []string{
		"```js\nconsole.log(\"x\");\nconst x = 1;\n```\n",
		"```sh\ngo test ./...\n```\n",
		"```text\nhello world\n```\n",
		"```yaml\nkey: value\n```\n",
		"<pre>hello</pre>\n",
		"<code>x</code>\n",
	} {
		if fs := scan(t, md); len(fs) != 0 {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestBannedLinkIsCaseInsensitive(t *testing.T) {
	for _, md := range []string{"[x](security-findings.md)", "[x](audit-x.md)", "[x](Global_Review.md)", "[x](.TASKS/x)", "[x](docs/Audit-2025.MD)"} {
		if fs := scan(t, md+"\n"); !onlyRule(fs, lint.RuleBanned, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
	for _, md := range []string{"[x](docs/security/independent-audit-scope.md)", "[x](AUDIT.md)", "[x](my.tasks/x)"} {
		if fs := scan(t, md+"\n"); len(fs) != 0 {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestBurdenHiddenByHomoglyphsFails(t *testing.T) {
	for _, md := range []string{"Remеmber to rotate.", "Rеmеmbеr tо rotate.", "Ｒｅｍｅｍｂｅｒ to rotate.", "ΜUST also set it."} {
		if fs := scan(t, md+"\n"); !onlyRule(fs, lint.RuleBurden, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
}
