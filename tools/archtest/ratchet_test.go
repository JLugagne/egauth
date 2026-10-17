package archtest_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

const (
	baselineSource  = "exemption_baseline.go"
	archtestRepoRel = "tools/archtest"
	ratchetBaseEnv  = "EGAUTH_RATCHET_BASE_REF"
	guardG06        = archtest.GuardID("G06")
	guardG07a       = archtest.GuardID("G07a")
)

var permanentEntries = []archtest.PermanentEntry{
	{Guard: guardG07a, Symbol: archtest.ModulePath + "/adapters/otel.Options.ExportPII", RemovedBy: archtest.Permanent},
	{Guard: guardG07a, Symbol: archtest.ModulePath + "/event.AccountDisabled", RemovedBy: archtest.Permanent},
	{Guard: guardG07a, Symbol: archtest.ModulePath + "/event.InsecureConfiguration", RemovedBy: archtest.Permanent},
	{Guard: guardG07a, Symbol: archtest.ModulePath + "/kek.LegacyOpener", RemovedBy: archtest.WPV018},
	{Guard: guardG07a, Symbol: archtest.ModulePath + "/kek.LegacyLocalV016", RemovedBy: archtest.WPV018},
	{Guard: guardG07a, Symbol: archtest.ModulePath + ".UpgradeSecretsV016", RemovedBy: archtest.WPV018},
	{Guard: archtest.G14, Symbol: "errors.As", RemovedBy: archtest.Permanent},
	{Guard: archtest.G14, Symbol: "net/http.Flusher", RemovedBy: archtest.Permanent},
	{Guard: archtest.G14, Symbol: "net/http.Hijacker", RemovedBy: archtest.Permanent},
}

var specLegacyPrefixes = []string{
	"webapp", "tokens", "sessions", "identity", "mfa", "passkey", "oauth", "otp", "issuance",
	"authflow", "origin", "revocation", "janitor", "health", "ratelimit", "keystore",
	"internal/loginflowtest", "internal/securitydefaults", "internal/doctest", "internal/httputil",
	"internal/safehttp",
	"adapters/pgx/identity", "adapters/pgx/sessions", "adapters/pgx/tokens", "adapters/pgx/mfa",
	"adapters/pgx/otp", "adapters/pgx/passkey", "adapters/pgx/oauth", "adapters/pgx/keystore",
	"adapters/pgx/internal/pgxmigrate",
	"test", "adapters/pgx/test", "e2e-security", "internal/examplekey",
}

func TestRatchetCountsMatchLists(t *testing.T) {
	lists := archtest.Lists()
	if len(lists) == 0 {
		t.Fatal("no exemption list registered")
	}
	for _, msg := range archtest.CheckCounts(lists) {
		t.Error(msg)
	}
}

func TestRatchetDetectsDrift(t *testing.T) {
	e := archtest.Exemption{Guard: archtest.G01, Symbol: "x", RemovedBy: archtest.WP16}
	grown := archtest.ExemptionList{Guard: archtest.G01, MaxEntries: 1, Entries: []archtest.Exemption{e, e}}
	shrunk := archtest.ExemptionList{Guard: archtest.G02, MaxEntries: 2, Entries: []archtest.Exemption{e}}
	exact := archtest.ExemptionList{Guard: archtest.G03, MaxEntries: 1, Entries: []archtest.Exemption{e}}
	if got := archtest.CheckCounts([]archtest.ExemptionList{grown, shrunk, exact}); len(got) != 2 {
		t.Fatalf("want drift reported for the grown and the shrunk list only, got %v", got)
	}
	if got := archtest.CheckCounts([]archtest.ExemptionList{exact, exact}); len(got) != 1 {
		t.Fatalf("a guard registering two lists must be reported: %v", got)
	}
}

func TestRatchetMatchesBaseline(t *testing.T) {
	baseline, err := archtest.LoadBaseline(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range archtest.CheckBaseline(archtest.BaselineLines(archtest.Lists()), baseline) {
		t.Error(msg)
	}
}

func TestRatchetBaselineSourceParses(t *testing.T) {
	src, err := os.ReadFile(baselineSource)
	if err != nil {
		t.Fatal(err)
	}
	got, err := archtest.ParseBaselineSource(src)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, archtest.CoreBaseline()) {
		t.Fatalf("the base-revision parser must read the same lines as the compiled baseline:\n%v\n%v", got, archtest.CoreBaseline())
	}
}

func TestRatchetBaselineRejectsGrowthEvenWithRaisedConstant(t *testing.T) {
	e := archtest.Exemption{Guard: archtest.G01, Symbol: "a", RemovedBy: archtest.WP16}
	extra := archtest.Exemption{Guard: archtest.G01, Symbol: "b", RemovedBy: archtest.WP16}
	baseline := archtest.BaselineLines([]archtest.ExemptionList{{Guard: archtest.G01, MaxEntries: 1, Entries: []archtest.Exemption{e}}})
	grown := []archtest.ExemptionList{{Guard: archtest.G01, MaxEntries: 2, Entries: []archtest.Exemption{e, extra}}}
	if counts := archtest.CheckCounts(grown); len(counts) != 0 {
		t.Fatalf("the constant was raised, counts agree: %v", counts)
	}
	got := archtest.CheckBaseline(archtest.BaselineLines(grown), baseline)
	if len(got) != 1 || !strings.Contains(got[0], "grew") {
		t.Fatalf("growth must be reported against the baseline: %v", got)
	}
	if got := archtest.CheckBaseline(baseline, archtest.BaselineLines(grown)); len(got) != 1 || !strings.Contains(got[0], "removed") {
		t.Fatalf("a shrink must require shrinking the baseline: %v", got)
	}
}

func TestRatchetLegacyPrefixesOnlyShrink(t *testing.T) {
	got := archtest.LegacyRelPrefixes()
	if len(got) != archtest.LegacyPrefixCount {
		t.Fatalf("LegacyPrefixCount is %d but %d prefixes are listed", archtest.LegacyPrefixCount, len(got))
	}
	for _, p := range got {
		if !slices.Contains(specLegacyPrefixes, p) {
			t.Errorf("legacy prefix %s is not a package of DESIGN.md section 10.1: the legacy list may only shrink", p)
		}
	}
}

func TestRatchetLegacyEntriesNeedNoBaseline(t *testing.T) {
	legacy := archtest.LegacyExemptions(guardG06)
	l := archtest.ExemptionList{Guard: guardG06, MaxEntries: len(legacy), Entries: legacy}
	if lines := archtest.BaselineLines([]archtest.ExemptionList{l}); len(lines) != 0 {
		t.Fatalf("a guard registered by another task must be able to exempt the legacy prefixes without a baseline line: %v", lines)
	}
	forged := archtest.ExemptionList{Guard: guardG06, MaxEntries: 1, Entries: []archtest.Exemption{
		{Guard: guardG06, Symbol: archtest.ModulePath + "/store/...", RemovedBy: archtest.WP16},
	}}
	if lines := archtest.BaselineLines([]archtest.ExemptionList{forged}); len(lines) != 1 {
		t.Fatalf("a prefix outside section 10.1 is not a legacy entry and must be baselined: %v", lines)
	}
}

func TestRatchetNewGuardListIsBaselinedUnderItsTestdata(t *testing.T) {
	dir := t.TempDir()
	typed := archtest.Exemption{Guard: guardG07a, Symbol: archtest.ModulePath + "/kek.LegacyOpener", RemovedBy: archtest.WPV018}
	writeBaseline(t, dir, "g07", "G07a\t"+typed.Symbol+"\t\tv0.18\n")
	baseline, err := archtest.LoadBaseline(dir)
	if err != nil {
		t.Fatal(err)
	}
	repoBaseline, err := archtest.LoadBaseline(".")
	if err != nil {
		t.Fatal(err)
	}
	baseline = append(baseline, repoBaseline...)
	entries := append(archtest.LegacyExemptions(guardG07a), typed)
	lists := append(archtest.Lists(), archtest.ExemptionList{Guard: guardG07a, MaxEntries: len(entries), Entries: entries})
	if msgs := archtest.CheckBaseline(archtest.BaselineLines(lists), baseline); len(msgs) != 0 {
		t.Fatalf("a guard owning testdata/g07 must introduce its list there: %v", msgs)
	}
	writeBaseline(t, dir, "g06", "G01\tsmuggled\t\tWP16\n")
	if _, err := archtest.LoadBaseline(dir); err == nil {
		t.Fatal("a baseline file holding the lines of another guard must be rejected")
	}
}

func writeBaseline(t *testing.T, dir, sub, content string) {
	t.Helper()
	p := filepath.Join(dir, "testdata", sub)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, archtest.BaselineFileName), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRatchetShrinkOnlyAgainstBase(t *testing.T) {
	base := []string{"G01\ta\t\tWP16", "G01\tb\t\tWP16"}
	if got := archtest.CheckShrinkOnly(base, []string{"G01\ta\t\tWP16"}); len(got) != 0 {
		t.Fatalf("a shrink is allowed: %v", got)
	}
	if got := archtest.CheckShrinkOnly(base, []string{"G01\ta\t\tWP16", "G01\tc\t\tWP16"}); len(got) != 1 {
		t.Fatalf("growth of an existing list must be reported: %v", got)
	}
	if got := archtest.CheckShrinkOnly(base, []string{"G06\tx\t\tWP16"}); len(got) != 0 {
		t.Fatalf("a new guard may introduce its list: %v", got)
	}
}

func TestRatchetBaselineNeverGrowsSinceBaseRef(t *testing.T) {
	ws := repoWorkspace(t)
	ref := ratchetBaseRef(t, ws.Root)
	base, found := baselineAtRef(t, ws.Root, ref)
	if !found {
		t.Skipf("no ratchet baseline at %s", ref)
	}
	for _, msg := range archtest.CheckShrinkOnly(base, archtest.BaselineLines(archtest.Lists())) {
		t.Error(msg)
	}
}

func ratchetBaseRef(t *testing.T, root string) string {
	t.Helper()
	if ref := os.Getenv(ratchetBaseEnv); ref != "" {
		return ref
	}
	for _, candidate := range []string{"main", "origin/main"} {
		out, err := exec.Command("git", "-C", root, "merge-base", "HEAD", candidate).Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	if os.Getenv("CI") != "" {
		t.Fatal(ratchetBaseEnv + " must name the merge base in CI (fetch enough history for it); the shrink-only ratchet cannot run")
	}
	t.Skip(ratchetBaseEnv + " is not set and no merge base with main was found")
	return ""
}

func baselineAtRef(t *testing.T, root, ref string) ([]string, bool) {
	t.Helper()
	src, err := exec.Command("git", "-C", root, "show", ref+":"+archtestRepoRel+"/"+baselineSource).Output()
	if err != nil {
		return nil, false
	}
	lines, err := archtest.ParseBaselineSource(src)
	if err != nil {
		t.Fatal(errors.Join(errors.New("parse the baseline at "+ref), err))
	}
	files, err := exec.Command("git", "-C", root, "ls-tree", "-r", "--name-only", ref, "--", archtestRepoRel+"/testdata").Output()
	if err != nil {
		t.Fatal(errors.Join(errors.New("list the testdata baselines at "+ref), err))
	}
	for _, f := range strings.Split(strings.TrimSpace(string(files)), "\n") {
		if !strings.HasSuffix(f, "/"+archtest.BaselineFileName) {
			continue
		}
		data, err := exec.Command("git", "-C", root, "show", ref+":"+f).Output()
		if err != nil {
			t.Fatal(errors.Join(errors.New("read "+f+" at "+ref), err))
		}
		lines = append(lines, archtest.ParseBaseline(string(data))...)
	}
	slices.Sort(lines)
	return lines, true
}

func TestRatchetEmptyAtRelease(t *testing.T) {
	ws := repoWorkspace(t)
	version, err := archtest.ReleaseVersion(ws.Root)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range archtest.CheckRelease(version, archtest.Lists(), permanentEntries) {
		t.Error(msg)
	}
	if strings.HasSuffix(version, "-dev") {
		return
	}
	for _, msg := range archtest.CheckRootImportAllowances(ws, archtest.DefaultConfig()) {
		t.Error(msg)
	}
}

func TestRatchetReleaseRejectsLeftovers(t *testing.T) {
	legacy := archtest.ExemptionList{Guard: archtest.G01, MaxEntries: 1, Entries: []archtest.Exemption{
		{Guard: archtest.G01, Symbol: archtest.ModulePath + "/tokens/...", RemovedBy: archtest.WP16},
	}}
	if got := archtest.CheckRelease("0.17.0", []archtest.ExemptionList{legacy}, permanentEntries); len(got) != 1 {
		t.Fatalf("a legacy entry must fail a release: %v", got)
	}
	if got := archtest.CheckRelease("0.17.0-dev", []archtest.ExemptionList{legacy}, permanentEntries); len(got) != 0 {
		t.Fatalf("dev versions tolerate entries: %v", got)
	}
}

func TestRatchetReleaseAllowsOnlyPermanentTypedEntries(t *testing.T) {
	permanent := archtest.ExemptionList{Guard: archtest.G14, MaxEntries: 3, Entries: []archtest.Exemption{
		{Guard: archtest.G14, Symbol: "errors.As", RemovedBy: archtest.Permanent},
		{Guard: archtest.G14, Symbol: "net/http.Flusher", RemovedBy: archtest.Permanent},
		{Guard: archtest.G14, Symbol: "net/http.Hijacker", RemovedBy: archtest.Permanent},
	}}
	otel := archtest.ExemptionList{Guard: guardG07a, MaxEntries: 1, Entries: []archtest.Exemption{
		{Guard: guardG07a, Symbol: archtest.ModulePath + "/adapters/otel.Options.ExportPII", RemovedBy: archtest.Permanent},
		{Guard: guardG07a, Symbol: archtest.ModulePath + "/event.AccountDisabled", RemovedBy: archtest.Permanent},
		{Guard: guardG07a, Symbol: archtest.ModulePath + "/event.InsecureConfiguration", RemovedBy: archtest.Permanent},
	}}
	if got := archtest.CheckRelease("0.17.0", []archtest.ExemptionList{permanent, otel}, permanentEntries); len(got) != 0 {
		t.Fatalf("permanent typed entries must survive a release: %v", got)
	}
	sneaky := archtest.ExemptionList{Guard: archtest.G14, MaxEntries: 1, Entries: []archtest.Exemption{
		{Guard: archtest.G14, Symbol: "fmt.Stringer", RemovedBy: archtest.Permanent},
	}}
	if got := archtest.CheckRelease("0.17.0", []archtest.ExemptionList{sneaky}, permanentEntries); len(got) != 1 {
		t.Fatalf("an entry marked permanent but absent from the allowlist must fail: %v", got)
	}
	unmarked := archtest.ExemptionList{Guard: archtest.G14, MaxEntries: 1, Entries: []archtest.Exemption{
		{Guard: archtest.G14, Symbol: "errors.As", RemovedBy: archtest.WP16},
	}}
	if got := archtest.CheckRelease("0.17.0", []archtest.ExemptionList{unmarked}, permanentEntries); len(got) != 1 {
		t.Fatalf("an allowlisted symbol not marked permanent must fail: %v", got)
	}
}

func TestRatchetReleaseToleratesEntriesRemovedByALaterRelease(t *testing.T) {
	g7a := archtest.ExemptionList{Guard: guardG07a, MaxEntries: 3, Entries: []archtest.Exemption{
		{Guard: guardG07a, Symbol: archtest.ModulePath + "/kek.LegacyOpener", RemovedBy: archtest.WPV018},
		{Guard: guardG07a, Symbol: archtest.ModulePath + "/kek.LegacyLocalV016", RemovedBy: archtest.WPV018},
		{Guard: guardG07a, Symbol: archtest.ModulePath + ".UpgradeSecretsV016", RemovedBy: archtest.WPV018},
	}}
	lists := []archtest.ExemptionList{g7a}
	if got := archtest.CheckRelease("0.17.0", lists, permanentEntries); len(got) != 0 {
		t.Fatalf("entries removed by v0.18 must survive the v0.17.0 release: %v", got)
	}
	if got := archtest.CheckRelease("v0.17.3", lists, permanentEntries); len(got) != 0 {
		t.Fatalf("entries removed by v0.18 must survive a v0.17 patch release: %v", got)
	}
	if got := archtest.CheckRelease("0.18.0", lists, permanentEntries); len(got) != 3 {
		t.Fatalf("entries removed by v0.18 must fail the v0.18.0 release: %v", got)
	}
	stray := []archtest.ExemptionList{{Guard: guardG07a, MaxEntries: 1, Entries: []archtest.Exemption{
		{Guard: guardG07a, Symbol: archtest.ModulePath + "/kek.Other", RemovedBy: archtest.WPV018},
	}}}
	if got := archtest.CheckRelease("0.17.0", stray, permanentEntries); len(got) != 1 {
		t.Fatalf("a versioned entry absent from the allowlist must fail a release: %v", got)
	}
	retyped := []archtest.ExemptionList{{Guard: guardG07a, MaxEntries: 1, Entries: []archtest.Exemption{
		{Guard: guardG07a, Symbol: archtest.ModulePath + "/adapters/otel.Options.ExportPII", RemovedBy: archtest.WPV018},
	}}}
	if got := archtest.CheckRelease("0.17.0", retyped, permanentEntries); len(got) != 1 {
		t.Fatalf("an allowlisted symbol must keep the RemovedBy pinned by the allowlist: %v", got)
	}
}

func TestRatchetPermanentGuardIDsAreKnown(t *testing.T) {
	known := map[archtest.GuardID]bool{}
	for _, g := range archtest.KnownGuards() {
		known[g] = true
	}
	for _, p := range permanentEntries {
		if !known[p.Guard] {
			t.Errorf("permanent entry %s names unknown guard %s", p.Symbol, p.Guard)
		}
	}
}

func TestRatchetEnvOverridesVersion(t *testing.T) {
	t.Setenv(archtest.ReleaseVersionEnv, "9.9.9")
	got, err := archtest.ReleaseVersion(t.TempDir())
	if err != nil || got != "9.9.9" {
		t.Fatalf("want override 9.9.9, got %q %v", got, err)
	}
}

func TestLegacyPackagesAreDeleted(t *testing.T) {
	ws := repoWorkspace(t)
	for _, rel := range specLegacyPrefixes {
		if _, err := os.Stat(filepath.Join(ws.Root, filepath.FromSlash(rel))); err == nil {
			t.Errorf("the legacy package %s of DESIGN.md section 10.1 still exists", rel)
		}
	}
	if archtest.LegacyPrefixCount != 0 || len(archtest.LegacyRelPrefixes()) != 0 {
		t.Errorf("the legacy exemption prefixes must be empty after the cutover")
	}
}
