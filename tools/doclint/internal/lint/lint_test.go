package lint_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
	"github.com/JLugagne/egauth/tools/doclint/internal/lint"
)

var (
	modOnce sync.Once
	modWS   *lint.Workspace
	modErr  error
	wsOnce  sync.Once
	wsWS    *lint.Workspace
	wsErr   error
)

func fixtureRoot(t *testing.T, name string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func modWorkspace(t *testing.T) *lint.Workspace {
	t.Helper()
	root := fixtureRoot(t, "mod")
	modOnce.Do(func() { modWS, modErr = lint.Load(root, []string{"GOWORK=off"}, ".") })
	if modErr != nil {
		t.Fatal(modErr)
	}
	return modWS
}

func depWorkspace(t *testing.T) *lint.Workspace {
	t.Helper()
	root := fixtureRoot(t, "ws")
	wsOnce.Do(func() {
		wsWS, wsErr = lint.Load(root, []string{"GOWORK=" + filepath.Join(root, "go.work")}, "core")
	})
	if wsErr != nil {
		t.Fatal(wsErr)
	}
	return wsWS
}

func rules(fs []lint.Finding) []lint.Rule {
	var out []lint.Rule
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

func scan(t *testing.T, md string) []lint.Finding {
	t.Helper()
	_, fs := lint.ScanMarkdown(modWorkspace(t), "x.md", md, false)
	return fs
}

func TestBurdenSentencesFail(t *testing.T) {
	phrases := []string{
		"You must also set the origin.", "Remember to rotate.", "Don't forget the cookie.", "do not forget it",
		"Pair it with Protect.", "The two values must match.", "Make sure that it is set.", "Apply on every route.",
		"You need to register it.", "Mount it at /auth.", "Set it in both places.", "Use the same origin as you passed.",
		"It must be identical.", "must equal the origin", "Pass to every handler.", "you should wire it",
		"Mount the handler at /x.", "Don’t forget the cookie.",
	}
	for _, p := range phrases {
		fs := scan(t, p+"\n")
		if len(fs) != 1 || fs[0].Rule != lint.RuleBurden {
			t.Errorf("%q: findings %v", p, fs)
		}
	}
}

func TestBurdenSentencesWrappedAcrossLinesFail(t *testing.T) {
	for _, md := range []string{
		"You must\nalso set the origin.\n",
		"Make\nsure to call it.\n",
		"Remember\nto rotate.\n",
		"Intro line.\n> You must\n> also set it.\n",
		"Use the same\norigin\nas you passed.\n",
		"you need\n  to   register it\n",
	} {
		fs := scan(t, md)
		if len(fs) != 1 || fs[0].Rule != lint.RuleBurden {
			t.Errorf("%q: findings %v", md, fs)
		}
	}
	fs := scan(t, "Intro.\nYou must\nalso set the origin.\n")
	if len(fs) != 1 || fs[0].Line != 2 {
		t.Fatalf("wrapped finding must sit on the line where the sentence starts: %v", fs)
	}
	if fs := scan(t, "You must\n\nalso note this.\n"); len(fs) != 0 {
		t.Fatalf("paragraph break must not join sentences: %v", fs)
	}
	if fs := scan(t, "- the same value\n- as before\n# Heading\n1. must\n2. also\n"); len(fs) != 0 {
		t.Fatalf("list items and headings must not join sentences: %v", fs)
	}
	if fs := scan(t, "- You must\n  also set it.\n"); len(fs) != 1 {
		t.Fatalf("a wrapped list item is one sentence: %v", fs)
	}
}

func TestBurdenEscapeRequiresResolvingTest(t *testing.T) {
	if fs := scan(t, "Remember to rotate. doclint:enforced-by alpha.TestEnforced\n"); len(fs) != 0 {
		t.Fatalf("resolving escape: %v", fs)
	}
	if fs := scan(t, "<!-- doclint:enforced-by alpha.TestEnforced -->\nRemember to rotate.\n"); len(fs) != 0 {
		t.Fatalf("previous-line escape: %v", fs)
	}
	fs := scan(t, "Remember to rotate. doclint:enforced-by alpha.TestMissing\n")
	if got := rules(fs); !slices.Equal(got, []lint.Rule{lint.RuleEnforced, lint.RuleBurden}) {
		t.Fatalf("unresolved escape must fail and not excuse: %v", fs)
	}
}

func TestBurdenEscapeAcceptsOnlyTestsAndSuites(t *testing.T) {
	for _, target := range []string{"alpha.New", "alpha.Mode", "alpha.Server", "alpha.Server.Start", "alphatest.Helper", "alpha.hidden"} {
		fs := scan(t, "Remember to rotate. doclint:enforced-by "+target+"\n")
		if got := rules(fs); !slices.Equal(got, []lint.Rule{lint.RuleEnforced, lint.RuleBurden}) {
			t.Errorf("%s must not excuse a burden sentence: %v", target, fs)
		}
	}
	for _, target := range []string{"alpha.TestEnforced", "alpha.ExampleNew", "alphatest.Run", "alphatest.Suite.Run"} {
		if fs := scan(t, "Remember to rotate. doclint:enforced-by "+target+"\n"); len(fs) != 0 {
			t.Errorf("%s must excuse: %v", target, fs)
		}
	}
}

func TestBurdenEscapeDoesNotReachDistantLines(t *testing.T) {
	fs := scan(t, "doclint:enforced-by alpha.TestEnforced\nFirst line.\nRemember to rotate.\n")
	if len(fs) != 1 || fs[0].Rule != lint.RuleBurden || fs[0].Line != 3 {
		t.Fatalf("escape must only cover its own and the next line: %v", fs)
	}
}

func TestBurdenInsideFencesIgnored(t *testing.T) {
	if fs := scan(t, "```text\nremember to rotate\n```\n"); len(fs) != 0 {
		t.Fatal(fs)
	}
}

func TestBannedLinksAndClaims(t *testing.T) {
	for _, b := range []string{
		"See [x](SECURITY-FINDINGS.md).", "See AUDIT-2025.md", "[r](GLOBAL_REVIEW.md)", "[t](.tasks/M11/DESIGN.md)",
		"Signatures verified against source.", "signatures VERIFIED against SOURCE",
	} {
		fs := scan(t, b+"\n")
		if len(fs) != 1 || fs[0].Rule != lint.RuleBanned {
			t.Errorf("%q: %v", b, fs)
		}
	}
	if fs := scan(t, "See [s](SECURITY.md).\n"); len(fs) != 0 {
		t.Fatal(fs)
	}
}

func TestBannedInsideFencedBlocks(t *testing.T) {
	fs := scan(t, "```text\nsee SECURITY-FINDINGS.md\nSignatures verified against source\n```\n")
	if got := rules(fs); !slices.Equal(got, []lint.Rule{lint.RuleBanned, lint.RuleBanned}) || fs[0].Line != 2 || fs[1].Line != 3 {
		t.Fatalf("banned content inside fences: %v", fs)
	}
	fs = scan(t, "~~~sh\ncat .tasks/x\n~~~\n")
	if len(fs) != 1 || fs[0].Rule != lint.RuleBanned {
		t.Fatalf("banned content inside tilde fences: %v", fs)
	}
}

func TestSymbolReferences(t *testing.T) {
	good := "`alpha.New` `alpha.Server` `alpha.Server.Start` `alpha.Server.Addr` `alpha.New()` `alpha.Mode` `http.Handler` `http.Server.ListenAndServe`\n"
	if fs := scan(t, good); len(fs) != 0 {
		t.Fatalf("good refs: %v", fs)
	}
	bad := []string{"`alpha.Missing`", "`alpha.Server.Nope`", "`nopkg.Thing`", "`alpha.hidden`x `alpha.New.Foo`", "`http.NoSuchThing`", "`alpha.Server.inner`"}
	for _, b := range bad {
		fs := scan(t, b+"\n")
		if len(fs) != 1 || fs[0].Rule != lint.RuleSymbol {
			t.Errorf("%q: %v", b, fs)
		}
	}
}

func TestSymbolReferenceForms(t *testing.T) {
	good := "`*alpha.Server` `&alpha.Server{}` `alpha.Server{Addr: \"x\"}` `alpha.New(cfg)` `[]alpha.Server` `...alpha.Server` `alpha.Generic[int]` `alpha.Generic.Get` `alpha.Doer.Do` `alpha.Config.Origin`\n"
	if fs := scan(t, good); len(fs) != 0 {
		t.Fatalf("good forms: %v", fs)
	}
	for _, b := range []string{"`*alpha.Nope`", "`&alpha.Nope{}`", "`alpha.Nope{X: 1}`", "`alpha.Nope(x)`", "`[]alpha.Nope`", "`alpha.Doer.Close`"} {
		fs := scan(t, b+"\n")
		if len(fs) != 1 || fs[0].Rule != lint.RuleSymbol {
			t.Errorf("%q: %v", b, fs)
		}
	}
}

func TestSymbolTestOnlyIsNotAPI(t *testing.T) {
	for _, b := range []string{"`alpha.TestEnforced`", "`alpha.ExampleNew`"} {
		fs := scan(t, b+"\n")
		if len(fs) != 1 || fs[0].Rule != lint.RuleSymbol {
			t.Errorf("%q: %v", b, fs)
		}
	}
	w := depWorkspace(t)
	for _, b := range []string{"`pgx.TestHelper`", "`pgx.TestOnly`"} {
		_, fs := lint.ScanMarkdown(w, "x.md", b+"\n", false)
		if len(fs) != 1 || fs[0].Rule != lint.RuleSymbol {
			t.Errorf("%q: %v", b, fs)
		}
	}
}

func TestSymbolResolvesDependenciesAndShadowedNames(t *testing.T) {
	w := depWorkspace(t)
	_, fs := lint.ScanMarkdown(w, "x.md", "`pgx.Tx` `pgx.Tx.Commit` `pgx.Store` `protocol.VerificationRequired` `core.Mode` `core.Tx.Commit`\n", false)
	if len(fs) != 0 {
		t.Fatalf("dependency and shadowed references: %v", fs)
	}
	_, fs = lint.ScanMarkdown(w, "x.md", "`pgx.Missing`\n", false)
	if len(fs) != 1 || fs[0].Rule != lint.RuleSymbol {
		t.Fatalf("missing dependency symbol: %v", fs)
	}
	if fs := scan(t, "`http.Local` `http.Handler`\n"); len(fs) != 0 {
		t.Fatalf("workspace package shadowing a std name: %v", fs)
	}
}

func TestEmbedMarkerRequired(t *testing.T) {
	fs := scan(t, "Intro\n\n```go\nx := 1\n```\n")
	if len(fs) != 1 || fs[0].Rule != lint.RuleEmbed || fs[0].Line != 3 {
		t.Fatal(fs)
	}
	if fs := scan(t, "```text\nx\n```\n"); len(fs) != 0 {
		t.Fatal(fs)
	}
}

func TestEmbedMarkerRequiredForEveryGoSpelling(t *testing.T) {
	for _, open := range []string{"```golang", "```Go", "```GO", "``` go", "```{.go}", "```go title=x", "~~~go", "````Golang"} {
		closing := strings.Repeat(open[:1], len(open)-len(strings.TrimLeft(open, open[:1])))
		fs := scan(t, open+"\nx := 1\n"+closing+"\n")
		if len(fs) != 1 || fs[0].Rule != lint.RuleEmbed {
			t.Errorf("%q: %v", open, fs)
		}
	}
	for open, body := range map[string]string{"```gotemplate": "{{ $x := .Name }}", "```sh": "x=1 go test ./..."} {
		if fs := scan(t, open+"\n"+body+"\n```\n"); len(fs) != 0 {
			t.Errorf("%q: %v", open, fs)
		}
	}
	if fs := scan(t, "```\nmake test\n```\n"); len(fs) != 0 {
		t.Errorf("untagged non-Go block: %v", fs)
	}
}

func TestEmbedUnterminatedGoBlock(t *testing.T) {
	fs := scan(t, "<!-- embed: alpha/example_test.go#ExampleNew -->\n```go\nx := 1\n")
	if len(fs) != 1 || fs[0].Rule != lint.RuleEmbed {
		t.Fatal(fs)
	}
}

func TestEmbedCheckAndWrite(t *testing.T) {
	w := modWorkspace(t)
	marker := "<!-- embed: alpha/example_test.go#ExampleNew -->\n"
	stale := marker + "```go\nold()\n```\n"
	_, fs := lint.ScanMarkdown(w, "x.md", stale, false)
	if len(fs) != 1 || fs[0].Rule != lint.RuleEmbed || !strings.Contains(fs[0].Message, "differs") {
		t.Fatalf("check: %v", fs)
	}
	updated, fs := lint.ScanMarkdown(w, "x.md", stale, true)
	if len(fs) != 0 {
		t.Fatalf("write: %v", fs)
	}
	want := marker + "```go\ns := alpha.New()\ns.Start()\nfmt.Println(\"ok\")\n// Output: ok\n```\n"
	if updated != want {
		t.Fatalf("regenerated:\n%s\nwant:\n%s", updated, want)
	}
	if _, fs := lint.ScanMarkdown(w, "x.md", updated, false); len(fs) != 0 {
		t.Fatalf("idempotent check: %v", fs)
	}
}

func TestEmbedBrokenTargets(t *testing.T) {
	for _, m := range []string{
		"alpha/example_test.go#ExampleNope",
		"alpha/none_test.go#ExampleNew",
		"alpha/ignored_test.go#ExampleIgnored",
		"alpha/ignored_test.go#Anything",
		"alpha/testdata/hidden_test.go#ExampleHidden",
		"alpha/alpha.go#New",
		"alpha/alpha_test.go#TestEnforced",
		"alpha/example_test.go#Anything",
		"alpha/example_test.go#ExampleWithArg",
	} {
		_, fs := lint.ScanMarkdown(modWorkspace(t), "x.md", "<!-- embed: "+m+" -->\n```go\nx\n```\n", true)
		if len(fs) != 1 || fs[0].Rule != lint.RuleEmbed {
			t.Errorf("%s: %v", m, fs)
		}
	}
}

func TestScanCodeCoversEveryExportedDocComment(t *testing.T) {
	w := modWorkspace(t)
	fs := lint.ScanCode(w, nil)
	var got []string
	for _, f := range fs {
		if f.Rule != lint.RuleBurden {
			t.Errorf("unexpected rule: %v", f)
		}
		got = append(got, f.File+":"+strconv.Itoa(f.Line))
	}
	want := []string{
		"alpha/alpha.go:10",
		"alpha/block.go:6",
		"alpha/fields.go:5",
		"alpha/fields.go:8",
		"alpha/fields.go:11",
		"alpha/fields.go:21",
		"alpha/fields.go:25",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v\nwant %v\n%v", got, want, fs)
	}
	if fs := lint.ScanCode(w, []string{"alpha"}); len(fs) != 0 {
		t.Fatalf("legacy skip: %v", fs)
	}
}

func TestDefaultLegacyDirsTrackArchtestRegistry(t *testing.T) {
	if got, want := lint.DefaultLegacyDirs(), archtest.LegacyRelPrefixes(); !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestRunWritesEmbedsInEveryDocFile(t *testing.T) {
	dir := t.TempDir()
	copyTree(t, fixtureRoot(t, "mod"), dir)
	stale := "<!-- embed: alpha/example_test.go#ExampleNew -->\n```go\nold\n```\n"
	for _, f := range []string{"README.md", "llms.txt", ".llms/guide.txt", "docs/a/b.md"} {
		writeFile(t, filepath.Join(dir, f), stale)
	}
	opts := lint.Options{Root: dir, Docs: true, Modules: []string{"."}, Env: []string{"GOWORK=off"}}
	fs, err := lint.Run(opts)
	if err != nil || len(fs) != 4 {
		t.Fatalf("check: %v %v", fs, err)
	}
	opts.Write = true
	if fs, err = lint.Run(opts); err != nil || len(fs) != 0 {
		t.Fatalf("write: %v %v", fs, err)
	}
	opts.Write = false
	if fs, err = lint.Run(opts); err != nil || len(fs) != 0 {
		t.Fatalf("recheck: %v %v", fs, err)
	}
}

func TestRunRefusesUncompilableTree(t *testing.T) {
	dir := t.TempDir()
	copyTree(t, fixtureRoot(t, "mod"), dir)
	writeFile(t, filepath.Join(dir, "alpha", "broken_test.go"), "package alpha_test\n\nfunc ExampleBroken() { doesNotCompile() }\n")
	if _, err := lint.Run(lint.Options{Root: dir, Docs: true, Modules: []string{"."}, Env: []string{"GOWORK=off"}}); err == nil {
		t.Fatal("a tree that does not compile must be a load error")
	}
}

func workspaceCopy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	copyTree(t, fixtureRoot(t, "mod"), dir)
	writeFile(t, filepath.Join(dir, "go.work"), "go 1.26\n\nuse .\n")
	writeFile(t, filepath.Join(dir, "README.md"), "<!-- embed: alpha/example_test.go#ExampleNew -->\n```go\ns := alpha.New()\ns.Start()\nfmt.Println(\"ok\")\n// Output: ok\n```\n")
	return dir
}

func TestMainFindsRootFromSubdirectory(t *testing.T) {
	dir := workspaceCopy(t)
	t.Chdir(filepath.Join(dir, "alpha"))
	var out, errOut bytes.Buffer
	if code := lint.Main([]string{"-docs", "-check", "-modules", "."}, &out, &errOut); code != 0 {
		t.Fatalf("docs: exit %d\n%s%s", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := lint.Main([]string{"-code", "-modules", ".", "-legacy", ""}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "alpha/alpha.go:10") {
		t.Fatalf("code: exit %d\n%s%s", code, out.String(), errOut.String())
	}
	if code := lint.Main([]string{"-root", t.TempDir()}, &out, &errOut); code != 2 {
		t.Fatalf("root without go.work: exit %d", code)
	}
	if code := lint.Main([]string{"-write", "-check"}, &out, &errOut); code != 2 {
		t.Fatalf("exclusive flags: exit %d", code)
	}
}

func TestCommandRunsAsGoRunDoclint(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not on PATH")
	}
	dir := workspaceCopy(t)
	tools, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goBin, "run", "./doclint", "-check", "-docs", "-modules", ".", "-root", dir)
	cmd.Dir = tools
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cd tools && go run ./doclint -check: %v\n%s", err, out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
