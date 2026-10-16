package lint_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/doclint/internal/lint"
)

func TestBurdenHiddenByMultiLineHTMLTagFails(t *testing.T) {
	for _, md := range []string{
		"Remember <span\nclass=\"x\">to</span> rotate.\n",
		"Remember<span\ntitle=\"a>b\">to</span> rotate.\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleBurden, 1) || fs[0].Line != 1 {
			t.Errorf("%q: %v", md, fs)
		}
	}
	md := "Signatures <span\ntitle='a>b'>verified</span> against source.\n"
	if fs := scan(t, md); !onlyRule(fs, lint.RuleBanned, 1) {
		t.Errorf("%q: %v", md, fs)
	}
}

func TestUnterminatedQuotedAttributeDoesNotHideBurden(t *testing.T) {
	md := "Intro <x \"\nRemember to rotate.\n\">.\n"
	if fs := scan(t, md); !onlyRule(fs, lint.RuleBurden, 1) || fs[0].Line != 2 {
		t.Fatalf("%q: %v", md, fs)
	}
}

func TestBannedReferenceSplitByInlineHTMLFails(t *testing.T) {
	for _, md := range []string{
		"See GLOBAL<b></b>_REVIEW.md.",
		"See SECURITY-<span title=\"a>b\">FINDINGS</span>.md.",
		"See <i>.</i>tasks for details.",
	} {
		if fs := scan(t, md+"\n"); !onlyRule(fs, lint.RuleBanned, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
}
