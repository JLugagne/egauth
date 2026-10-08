package lint_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/doclint/internal/lint"
)

func TestBurdenHiddenByInlineHTMLTagsFails(t *testing.T) {
	for _, md := range []string{
		"Remember<br>to rotate.\n",
		"Remember<br/>to rotate.\n",
		"Remember<span title=\"a>b\">to</span> rotate.\n",
		"Remember <span title='x>y'>to</span> rotate.\n",
		"Remem<b>ber</b> to rotate.\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleBurden, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
	for _, md := range []string{
		"Signatures<br>verified against source.\n",
		"Signatures <span title=\"a>b\">verified</span> against source.\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleBanned, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestBannedLinkWithBackslashEscapesFails(t *testing.T) {
	for _, md := range []string{
		"[x](GLOBAL\\_REVIEW.md)",
		"[x](SECURITY\\-FINDINGS.md)",
		"[x](AUDIT\\-2025.md)",
		"[x](\\.tasks/x)",
		"[x](GLOBAL&#92;_REVIEW.md)",
	} {
		if fs := scan(t, md+"\n"); !onlyRule(fs, lint.RuleBanned, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestBannedLinkToTasksDirectoryFails(t *testing.T) {
	for _, md := range []string{"[x](.tasks)", "[x](./.tasks)", "See .tasks.", "[x](.tasks#plan)"} {
		if fs := scan(t, md+"\n"); !onlyRule(fs, lint.RuleBanned, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
	for _, md := range []string{"[x](my.tasks)", "[x](.tasksfoo)", "[x](x.tasks.md)"} {
		if fs := scan(t, md+"\n"); len(fs) != 0 {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestSymbolReferenceAfterOperatorsAndCallsResolves(t *testing.T) {
	for _, b := range []string{
		"`-alpha.Nope`", "`x = -alpha.Nope`", "`<-alpha.Nope`", "`v := <-alpha.Nope`",
		"`(*alpha.Server).Nope`", "`(alpha.Server).Nope`", "`alpha.New().Nope`", "`alpha.New().Addr.Nope`",
	} {
		if fs := scan(t, b+"\n"); !onlyRule(fs, lint.RuleSymbol, 1) {
			t.Errorf("%q: %v", b, fs)
		}
	}
	good := "`-alpha.Mode` `<-alpha.Ch` `(*alpha.Server).Start` `alpha.New().Start()` `alpha.New().Addr` `http.HandlerFunc(alpha.Handle).ServeHTTP` `foo-bar.Baz` `--flag.Name`\n"
	if fs := scan(t, good); len(fs) != 0 {
		t.Fatalf("good references: %v", fs)
	}
}

func TestSymbolReferenceInMultiLineCodeSpanResolves(t *testing.T) {
	fs := scan(t, "Call `x :=\nalpha.Missing()` first.\n")
	if !onlyRule(fs, lint.RuleSymbol, 1) {
		t.Fatalf("multi-line code span: %v", fs)
	}
}

func TestVariableFallbackDoesNotHideDeletedPackage(t *testing.T) {
	if fs := scan(t, "`session.Start`\n"); !onlyRule(fs, lint.RuleSymbol, 1) {
		t.Fatalf("a long local variable name must not stand in for a deleted package: %v", fs)
	}
	if fs := scan(t, "`srv.Addr` `ctx.Err()` `r.Host`\n"); len(fs) != 0 {
		t.Fatalf("short variable references: %v", fs)
	}
}

func TestGoInIndentedCodeBlockFails(t *testing.T) {
	for _, md := range []string{
		"Intro.\n\n    s := alpha.New()\n    s.Start()\n",
		"    package main\n\n    func main() {}\n",
		"Intro.\n\n\tfunc Run() {}\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleEmbed, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
	for _, md := range []string{
		"Intro.\n\n    go test ./...\n",
		"- item\n\n    continued paragraph text\n",
		"Intro.\n\n    hello world\n",
	} {
		if fs := scan(t, md); len(fs) != 0 {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestGoWithElisionsOutsideGoFencesNeedsMarker(t *testing.T) {
	for _, md := range []string{
		"```\ns := alpha.New()\n...\ns.Start()\n```\n",
		"```text\nfunc Run() {\n\t...\n}\n```\n",
		"```\ncfg := alpha.Config{...}\n```\n",
		"```\nx := alpha.New(...)\n```\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleEmbed, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
	for _, md := range []string{"```\ngo test ./...\n```\n", "```\nfoo\n...\nbar\n```\n"} {
		if fs := scan(t, md); len(fs) != 0 {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestBurdenHiddenByCompatibilityLettersFails(t *testing.T) {
	for _, md := range []string{
		"\U0001D411\U0001D41E\U0001D426\U0001D41E\U0001D426\U0001D41B\U0001D41E\U0001D42B to rotate.",
		"ʀᴇᴍᴇᴍʙᴇʀ ᴛᴏ rotate.",
		"You \U0001D696\U0001D69E\U0001D69C\U0001D69D also set it.",
	} {
		if fs := scan(t, md+"\n"); !onlyRule(fs, lint.RuleBurden, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestEscapeExcusesOneBurdenInUnpunctuatedRun(t *testing.T) {
	fs := scan(t, "Remember to rotate\nyou must also set X doclint:enforced-by alpha.TestEnforced\n")
	if !onlyRule(fs, lint.RuleBurden, 1) || fs[0].Line != 1 {
		t.Fatalf("one escape must not excuse a whole unpunctuated run: %v", fs)
	}
	if fs := scan(t, "You must\nalso set X doclint:enforced-by alpha.TestEnforced\n"); len(fs) != 0 {
		t.Fatalf("escape ending a wrapped burden: %v", fs)
	}
}
