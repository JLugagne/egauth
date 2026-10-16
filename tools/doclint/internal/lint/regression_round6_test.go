package lint_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/doclint/internal/lint"
)

func TestBurdenHiddenByLinkDestinationWithParenthesisFails(t *testing.T) {
	for _, md := range []string{
		"[Remember](a(b)c) to rotate.\n",
		"[Remember](<a)b>) to rotate.\n",
		"[Remember](x \"a)b\") to rotate.\n",
		"[Remember](x 'a)b') to rotate.\n",
		"[Remember](x (a\\)b)) to rotate.\n",
		"[You must](x \"(t)\") also set it.\n",
		"[Remember](a\\)b) to rotate.\n",
		"[Remember](a((b))c) to rotate.\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleBurden, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
	md := "[Signatures](a(b)c) verified against source.\n"
	if fs := scan(t, md); !onlyRule(fs, lint.RuleBanned, 1) {
		t.Errorf("%q: %v", md, fs)
	}
}

func TestLinkDestinationWithParenthesisDoesNotLeakIntoText(t *testing.T) {
	for _, md := range []string{
		"See [the docs](a(remember to)b) for details.\n",
		"See [the docs](<x remember to y>) for details.\n",
		"See [the docs](x \"remember to\") for details.\n",
	} {
		if fs := scan(t, md); len(fs) != 0 {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestBurdenSplitByMultiLineCommentInsideWordFails(t *testing.T) {
	for _, md := range []string{
		"Remem<!--\n-->ber to rotate.\n",
		"Remem<!--\nx\n-->ber to rotate.\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleBurden, 1) || fs[0].Line != 1 {
			t.Errorf("%q: %v", md, fs)
		}
	}
	md := "Signa<!--\n-->tures verified against source.\n"
	if fs := scan(t, md); !onlyRule(fs, lint.RuleBanned, 1) {
		t.Errorf("%q: %v", md, fs)
	}
}

func TestBurdenSplitByFootnoteReferenceFails(t *testing.T) {
	for _, md := range []string{
		"Remember[^1] to rotate.\n",
		"You must[^note-a] also set it.\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleBurden, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestBannedAuditLinkWithSpaceInAngleDestinationFails(t *testing.T) {
	for _, md := range []string{"[x](<AUDIT-2025 q.md>)", "[x](<docs/AUDIT 2025.md>)"} {
		if fs := scan(t, md+"\n"); !onlyRule(fs, lint.RuleBanned, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestSymbolReferenceAfterUnspacedOperatorResolves(t *testing.T) {
	for _, b := range []string{
		"`alpha.Server{}.Nope`", "`x-alpha.Nope`", "`x/alpha.Nope`", "`x:alpha.Nope`", "`y<alpha.Nope`",
	} {
		if fs := scan(t, b+"\n"); !onlyRule(fs, lint.RuleSymbol, 1) {
			t.Errorf("%q: %v", b, fs)
		}
	}
}
