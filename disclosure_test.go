package egauth_test

import (
	"os"
	"strings"
	"testing"
)

// canonicalDisclosure is the single, build-enforced audit-status sentence. It MUST appear
// verbatim (modulo markdown decoration and line wrapping, see normalizeDisclosureText) on every
// first-point-of-contact surface listed in disclosureSurfaces. Editing this constant without
// updating every surface — or editing it away from any surface — fails the build. See TASK-009
// and AUDIT.md.
//
// Keep this wording in lock-step with README.md, doc.go, llms.txt, SECURITY.md, the CHANGELOG
// entry, and AUDIT.md. "AI-audited" must never read as a euphemism for "audited".
const canonicalDisclosure = "egauth's security review to date is an AI-driven audit only; " +
	"it has not had an independent third-party human security audit, and that risk is accepted " +
	"for v1.0 — pin a reviewed commit, commission your own audit, or wait if that trade-off is " +
	"unacceptable."

// disclosureSurfaces are the files whose first point of contact must carry the canonical
// disclosure. These are the four surfaces named in the Definition of Done (README, doc.go,
// llms.txt, SECURITY.md). AUDIT.md and the CHANGELOG also carry it and are each checked by their
// own dedicated test (TestDisclosureLedgerPresent, TestDisclosureChangelogPresent) so the
// four-surface DoD contract stays explicit.
var disclosureSurfaces = []string{
	"README.md",
	"doc.go",
	"llms.txt",
	"SECURITY.md",
}

// normalizeDisclosureText strips the markdown / godoc decoration that legitimately differs
// between surfaces (godoc "//" comment prefixes, blockquote ">" markers, "*" emphasis) and
// collapses all runs of whitespace — including the line wraps that split the sentence across
// several source lines — into single spaces. After normalization the canonical sentence is a
// plain substring on every surface, regardless of how each file wraps or decorates it.
func normalizeDisclosureText(s string) string {
	// Drop characters used only for decoration so the underlying prose lines up.
	replacer := strings.NewReplacer(
		"//", " ",
		">", " ",
		"*", " ",
		"\r", " ",
		"\n", " ",
		"\t", " ",
	)
	s = replacer.Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

// TestDisclosureSentencePresent asserts the canonical audit-status sentence appears verbatim
// (after decoration/whitespace normalization) on every required surface. Removing or editing the
// sentence away from any surface fails the build — this is the build-enforced honesty gate from
// TASK-009 / GitHub issue #19.
func TestDisclosureSentencePresent(t *testing.T) {
	want := normalizeDisclosureText(canonicalDisclosure)
	if want == "" {
		t.Fatal("canonicalDisclosure normalized to empty string; the constant is misconfigured")
	}

	for _, surface := range disclosureSurfaces {
		t.Run(surface, func(t *testing.T) {
			raw, err := os.ReadFile(surface)
			if err != nil {
				t.Fatalf("reading disclosure surface %q: %v", surface, err)
			}
			got := normalizeDisclosureText(string(raw))
			if !strings.Contains(got, want) {
				t.Errorf("audit-status disclosure missing or altered in %q.\n"+
					"Every first-point-of-contact surface must carry the canonical sentence verbatim:\n\n  %s\n\n"+
					"Restore it (see AUDIT.md / TASK-009) or update canonicalDisclosure in disclosure_test.go and ALL surfaces together.",
					surface, canonicalDisclosure)
			}
		})
	}
}

// TestDisclosureLedgerPresent guards the AUDIT.md ledger: it must exist, carry the canonical
// sentence, and keep an "Independent human audits" section so the honest "none yet" status stays
// visible until a real audit is recorded.
func TestDisclosureLedgerPresent(t *testing.T) {
	raw, err := os.ReadFile("AUDIT.md")
	if err != nil {
		t.Fatalf("reading AUDIT.md ledger: %v", err)
	}
	content := string(raw)

	if !strings.Contains(normalizeDisclosureText(content), normalizeDisclosureText(canonicalDisclosure)) {
		t.Errorf("AUDIT.md is missing the canonical audit-status sentence:\n\n  %s", canonicalDisclosure)
	}
	if !strings.Contains(content, "Independent human audits") {
		t.Error("AUDIT.md must keep an \"Independent human audits\" section (the empty ledger of external audits)")
	}
}

// TestDisclosureChangelogPresent guards the v1.0.0 CHANGELOG entry: it must carry the canonical
// audit-status sentence verbatim, matching the claim in AUDIT.md that the CHANGELOG is one of the
// surfaces the sentence is reused across.
func TestDisclosureChangelogPresent(t *testing.T) {
	raw, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatalf("reading CHANGELOG.md: %v", err)
	}
	content := string(raw)

	if !strings.Contains(normalizeDisclosureText(content), normalizeDisclosureText(canonicalDisclosure)) {
		t.Errorf("CHANGELOG.md is missing the canonical audit-status sentence:\n\n  %s", canonicalDisclosure)
	}
}
