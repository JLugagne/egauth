package archtest

import (
	"bufio"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// ReleaseVersionEnv overrides the VERSION file in dry runs of the release ratchet.
const ReleaseVersionEnv = "EGAUTH_RELEASE_VERSION"

// PermanentEntry is an exemption allowed to survive a release. The allowlist itself lives in the
// release test, never in production code. RemovedBy is pinned too: Permanent, or a release version
// such as WPV018 that the entry survives every earlier release of.
type PermanentEntry struct {
	Guard     GuardID
	Symbol    string
	RemovedBy WorkPackage
}

// BaselineFileName is the name of the baseline file kept under testdata/<BaselineDir>/ for a guard
// whose exemption list is declared outside the exemption files of this package.
const BaselineFileName = "ratchet.baseline"

// ReleaseVersion returns the version under test: the override variable, else the VERSION file.
func ReleaseVersion(root string) (string, error) {
	if v := strings.TrimSpace(os.Getenv(ReleaseVersionEnv)); v != "" {
		return v, nil
	}
	b, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// CheckCounts reports every list whose MaxEntries differs from its length, and every guard that
// registered more than one list.
func CheckCounts(lists []ExemptionList) []string {
	var out []string
	seen := map[GuardID]bool{}
	for _, l := range lists {
		if seen[l.Guard] {
			out = append(out, string(l.Guard)+": more than one exemption list registered")
		}
		seen[l.Guard] = true
		if l.MaxEntries != len(l.Entries) {
			out = append(out, string(l.Guard)+": maxEntries is "+strconv.Itoa(l.MaxEntries)+" but the list has "+strconv.Itoa(len(l.Entries))+" entries; update the constant in the same change")
		}
	}
	return out
}

// CheckRelease reports, when version is not a development version, every exemption left in the
// lists that is not in permanent with the same guard, symbol and RemovedBy, and every allowlisted
// entry whose RemovedBy names a release that is not later than version.
func CheckRelease(version string, lists []ExemptionList, permanent []PermanentEntry) []string {
	if strings.HasSuffix(version, "-dev") {
		return nil
	}
	var out []string
	for _, l := range lists {
		for _, e := range l.Entries {
			listed := slices.Contains(permanent, PermanentEntry{Guard: e.Guard, Symbol: e.Symbol, RemovedBy: e.RemovedBy})
			if !listed || (e.RemovedBy != Permanent && !removedAfter(e.RemovedBy, version)) {
				out = append(out, string(l.Guard)+": "+e.Symbol+" (removed by "+string(e.RemovedBy)+") remains in release "+version)
			}
		}
	}
	return out
}

func removedAfter(removedBy WorkPackage, version string) bool {
	removal, ok := parseVersion(string(removedBy))
	if !ok {
		return false
	}
	release, ok := parseVersion(version)
	return ok && slices.Compare(release[:], removal[:]) < 0
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	v, _, _ = strings.Cut(v, "+")
	v, _, _ = strings.Cut(v, "-")
	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// BaselineLines renders the non-legacy entries of the lists as the sorted, tab-separated lines of
// the committed ratchet baseline: guard, symbol, ReliesOnAbsenceOf and RemovedBy. Legacy entries
// (IsLegacy) are ratcheted by LegacyRelPrefixes instead.
func BaselineLines(lists []ExemptionList) []string {
	var out []string
	for _, l := range lists {
		for _, e := range l.Entries {
			if IsLegacy(e) {
				continue
			}
			out = append(out, strings.Join([]string{string(e.Guard), e.Symbol, e.ReliesOnAbsenceOf, string(e.RemovedBy)}, "\t"))
		}
	}
	slices.Sort(out)
	return out
}

// CoreBaseline returns the committed baseline of the lists declared in exemption_lists.go.
func CoreBaseline() []string {
	return ParseBaseline(coreBaseline)
}

// BaselineDir returns the testdata directory that holds the baseline of guard g: "g07" for G07a.
func BaselineDir(g GuardID) string {
	s := strings.ToLower(string(g))
	if len(s) > 3 {
		s = s[:3]
	}
	return s
}

// LoadBaseline returns CoreBaseline plus the lines of every testdata/*/ratchet.baseline under
// archtestDir. It fails when a file cannot be read or holds a line of a guard whose BaselineDir is
// not the file's directory, so a task can only baseline the guards it owns.
func LoadBaseline(archtestDir string) ([]string, error) {
	out := CoreBaseline()
	files, err := filepath.Glob(filepath.Join(archtestDir, "testdata", "*", BaselineFileName))
	if err != nil {
		return nil, errors.Join(errors.New("archtest: list baseline files"), err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, errors.Join(errors.New("archtest: read "+f), err)
		}
		dir := filepath.Base(filepath.Dir(f))
		for _, line := range ParseBaseline(string(data)) {
			g, _, _ := strings.Cut(line, "\t")
			if BaselineDir(GuardID(g)) != dir {
				return nil, errors.New("archtest: " + f + " holds a line of guard " + g + ": " + line)
			}
			out = append(out, line)
		}
	}
	slices.Sort(out)
	return out, nil
}

// ParseBaselineSource extracts the baseline from the source of exemption_baseline.go, so that the
// baseline of a base revision can be read without building it.
func ParseBaselineSource(src []byte) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), "exemption_baseline.go", src, 0)
	if err != nil {
		return nil, errors.Join(errors.New("archtest: parse baseline source"), err)
	}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "coreBaseline" || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return nil, errors.New("archtest: coreBaseline is not a string literal")
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				return nil, errors.Join(errors.New("archtest: unquote coreBaseline"), err)
			}
			return ParseBaseline(text), nil
		}
	}
	return nil, errors.New("archtest: coreBaseline not found")
}

// ParseBaseline reads baseline lines, ignoring blank lines and lines starting with "#".
func ParseBaseline(data string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	slices.Sort(out)
	return out
}

// CheckBaseline reports every difference between the registered entries and the committed
// baseline: an entry missing from the baseline means a list grew, an entry missing from the lists
// means the baseline must shrink in the same change.
func CheckBaseline(current, baseline []string) []string {
	var out []string
	for _, c := range current {
		if !slices.Contains(baseline, c) {
			out = append(out, "exemption list grew, lists may only shrink: "+c)
		}
	}
	for _, b := range baseline {
		if !slices.Contains(current, b) {
			out = append(out, "exemption removed: delete this line from the ratchet baseline: "+b)
		}
	}
	return out
}

// CheckShrinkOnly compares the baseline of a change with the baseline of its base revision and
// reports every added line whose guard already had a list at the base. A guard absent from the
// base may introduce its list once.
func CheckShrinkOnly(base, head []string) []string {
	known := map[string]bool{}
	for _, b := range base {
		g, _, _ := strings.Cut(b, "\t")
		known[g] = true
	}
	var out []string
	for _, h := range head {
		g, _, _ := strings.Cut(h, "\t")
		if known[g] && !slices.Contains(base, h) {
			out = append(out, "exemption added since the base revision, lists may only shrink: "+h)
		}
	}
	return out
}
