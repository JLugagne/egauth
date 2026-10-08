package lint_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/doclint/internal/lint"
)

func onlyRule(fs []lint.Finding, r lint.Rule, n int) bool {
	if len(fs) != n {
		return false
	}
	for _, f := range fs {
		if f.Rule != r {
			return false
		}
	}
	return true
}

func TestEmbedMarkerRequiredInsideContainers(t *testing.T) {
	for _, md := range []string{
		"> ```go\n> x := 1\n> ```\n",
		"- ```go\n  x := 1\n  ```\n",
		"* ```go\n  x := 1\n  ```\n",
		"1. ```go\n   x := 1\n   ```\n",
		"> - ```go\n>   x := 1\n>   ```\n",
		">> ```go\n>> x := 1\n>> ```\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleEmbed, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestContainerFenceBodyIsNotProse(t *testing.T) {
	for _, md := range []string{
		"> ```text\n> remember to rotate\n> ```\n",
		"- ```text\n  remember to rotate\n  ```\n",
	} {
		if fs := scan(t, md); len(fs) != 0 {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestContainerEndClosesFence(t *testing.T) {
	for _, md := range []string{
		"> ```text\n> x\n\nRemember to rotate.\n",
		"> ```text\n> x\nRemember to rotate.\n",
		"- ```text\n  x\nRemember to rotate.\n",
	} {
		fs := scan(t, md)
		if !onlyRule(fs, lint.RuleBurden, 1) {
			t.Errorf("%q: prose after the container must be scanned: %v", md, fs)
		}
	}
	if fs := scan(t, "> ```go\n> x := 1\nRemember to rotate.\n"); !slices.Equal(rules(fs), []lint.Rule{lint.RuleEmbed, lint.RuleBurden}) {
		t.Fatalf("a Go block cut by its container is unterminated: %v", fs)
	}
}

func TestBacktickInfoWithBacktickIsNotAFence(t *testing.T) {
	if fs := scan(t, "```x` remember to rotate\nmore text\n"); !onlyRule(fs, lint.RuleBurden, 1) {
		t.Fatalf("inline code must not open a fence: %v", fs)
	}
}

func TestEmbedInsideBlockquoteRegenerates(t *testing.T) {
	w := modWorkspace(t)
	stale := "> <!-- embed: alpha/example_test.go#ExampleNew -->\n> ```go\n> old\n> ```\n"
	if _, fs := lint.ScanMarkdown(w, "x.md", stale, false); !onlyRule(fs, lint.RuleEmbed, 1) {
		t.Fatalf("stale quoted block: %v", fs)
	}
	updated, fs := lint.ScanMarkdown(w, "x.md", stale, true)
	if len(fs) != 0 {
		t.Fatalf("write: %v", fs)
	}
	want := "> <!-- embed: alpha/example_test.go#ExampleNew -->\n> ```go\n> s := alpha.New()\n> s.Start()\n> fmt.Println(\"ok\")\n> // Output: ok\n> ```\n"
	if updated != want {
		t.Fatalf("regenerated:\n%s\nwant:\n%s", updated, want)
	}
	if _, fs := lint.ScanMarkdown(w, "x.md", updated, false); len(fs) != 0 {
		t.Fatalf("idempotent check: %v", fs)
	}
}

func TestBurdenHiddenByMarkupOrUnicodeSpacesFails(t *testing.T) {
	for _, md := range []string{
		"You **must** also set the origin.",
		"Remember *to* rotate.",
		"Make _sure_ to call it.",
		"[Pair it](x) with Protect.",
		"[Pair it][ref] with Protect.",
		"Remember <b>to</b> rotate.",
		"Remember to rotate.",
		"Remember to rotate.",
		"Remem​ber to rotate.",
		"Remember&nbsp;to rotate.",
		"You `must also` set it.",
		"Donʼt forget it.",
	} {
		if fs := scan(t, md+"\n"); !onlyRule(fs, lint.RuleBurden, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestBannedClaimWrappedOrMarkedUpFails(t *testing.T) {
	for _, md := range []string{
		"Signatures verified\nagainst source.\n",
		"Signatures **verified** against source.\n",
		"Signatures verified against source.\n",
		"```text\nSignatures verified\nagainst source\n```\n",
	} {
		if fs := scan(t, md); !onlyRule(fs, lint.RuleBanned, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
	if fs := scan(t, "Intro.\nSignatures verified\nagainst source.\n"); len(fs) != 1 || fs[0].Line != 2 {
		t.Fatalf("wrapped claim must sit on its first line: %v", fs)
	}
}

func TestBannedLinkEncodedFails(t *testing.T) {
	for _, md := range []string{
		"[x](SECURITY&#45;FINDINGS.md)",
		"[x](SECURITY%2DFINDINGS.md)",
	} {
		if fs := scan(t, md+"\n"); !onlyRule(fs, lint.RuleBanned, 1) {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestReceiverReferencesAreNotPackages(t *testing.T) {
	if fs := scan(t, "`r.Host` `ctx.Err()` `r.URL.Path` `s.Start()` `srv.Addr`\n"); len(fs) != 0 {
		t.Fatalf("receiver references: %v", fs)
	}
	for _, b := range []string{"`nopkg.Thing`", "`oldpkg.Server`", "`oldpkg.New()`", "`r.NoSuchMember`"} {
		if fs := scan(t, b+"\n"); !onlyRule(fs, lint.RuleSymbol, 1) {
			t.Errorf("%q: %v", b, fs)
		}
	}
}

func TestEscapeDoesNotLeakToNextSentence(t *testing.T) {
	fs := scan(t, "Remember to rotate. doclint:enforced-by alpha.TestEnforced\nYou must also set X.\n")
	if !onlyRule(fs, lint.RuleBurden, 1) || fs[0].Line != 2 {
		t.Fatalf("an inline escape must not excuse the next line: %v", fs)
	}
	if fs := scan(t, "You must\nalso set X. doclint:enforced-by alpha.TestEnforced\n"); len(fs) != 0 {
		t.Fatalf("escape at the end of a wrapped sentence: %v", fs)
	}
	if fs := scan(t, "- doclint:enforced-by alpha.TestEnforced\n  Remember to rotate.\n"); len(fs) != 0 {
		t.Fatalf("escape-only line: %v", fs)
	}
}

func TestSuiteEscapeRejectsHelpers(t *testing.T) {
	for _, target := range []string{"alphatest.RunTB", "alphatest.NewFake", "alpha.Check"} {
		fs := scan(t, "Remember to rotate. doclint:enforced-by "+target+"\n")
		if got := rules(fs); !slices.Equal(got, []lint.Rule{lint.RuleEnforced, lint.RuleBurden}) {
			t.Errorf("%s must not excuse a burden sentence: %v", target, fs)
		}
	}
}

func TestUntaggedFenceHoldingGoNeedsMarker(t *testing.T) {
	for _, body := range []string{
		"package main\n\nfunc main() {}",
		"func Run() {}",
		"s := alpha.New()\ns.Start()",
		"alpha.New().Start()",
		"if err != nil {\n\treturn err\n}",
	} {
		for _, fence := range []string{"```", "~~~"} {
			md := fence + "\n" + body + "\n" + fence + "\n"
			if fs := scan(t, md); !onlyRule(fs, lint.RuleEmbed, 1) {
				t.Errorf("%q: %v", md, fs)
			}
		}
	}
	for _, body := range []string{"go test ./...", "GOWORK=off go test", "make test", "hello world", "ls", "x = 1", "{\"a\": 1}", "curl -X POST https://x/y"} {
		md := "```\n" + body + "\n```\n"
		if fs := scan(t, md); len(fs) != 0 {
			t.Errorf("%q: %v", md, fs)
		}
	}
}

func TestDocLinksAndCodeTagsResolve(t *testing.T) {
	for _, b := range []string{"See [alpha.Missing].", "<code>alpha.Missing</code>", "See [*alpha.Missing].", "`[alpha.Missing]`", "See [alpha.Server.Nope]."} {
		if fs := scan(t, b+"\n"); !onlyRule(fs, lint.RuleSymbol, 1) {
			t.Errorf("%q: %v", b, fs)
		}
	}
	if fs := scan(t, "See [alpha.New], [alpha.Server.Start], <code>alpha.Mode</code>, [x], [ ] and [link](https://a.b).\n"); len(fs) != 0 {
		t.Fatalf("good links: %v", fs)
	}
}

func TestScanCodeBlockCommentStarPrefix(t *testing.T) {
	fs := lint.ScanCode(modWorkspace(t), nil)
	for _, f := range fs {
		if f.File == "alpha/block.go" && f.Line == 6 && f.Rule == lint.RuleBurden {
			return
		}
	}
	var got []string
	for _, f := range fs {
		got = append(got, f.String())
	}
	t.Fatalf("block comment with star prefixes not scanned:\n%s", strings.Join(got, "\n"))
}
