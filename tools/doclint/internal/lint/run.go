package lint

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/JLugagne/egauth/tools/archtest"
)

// Options selects what Run scans. Root is the absolute repository root, Modules the module
// directories relative to it (each loaded once) and Env the extra environment of every load, such
// as GOWORK=<Root>/go.work. Comments enables the exported doc comment scope, skipping the Legacy
// directories; Write regenerates embedded blocks in place instead of reporting them stale.
type Options struct {
	Root     string
	Docs     bool
	Comments bool
	Write    bool
	Legacy   []string
	Modules  []string
	Env      []string
}

// DocFiles lists the documentation files of the G26 scope under root, relative to it: README.md,
// SECURITY.md, CONTRIBUTING.md, llms.txt and every file under .llms/ and docs/.
func DocFiles(root string) ([]string, error) {
	var out []string
	for _, f := range []string{"README.md", "SECURITY.md", "CONTRIBUTING.md", "llms.txt"} {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			out = append(out, f)
		}
	}
	for _, dir := range []string{".llms", "docs"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				out = append(out, relPath(root, p))
			}
			return nil
		})
		if err != nil {
			return nil, errors.Join(errors.New("doclint: walk "+dir), err)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Run executes the selected scopes. With Write set, embedded blocks of every scanned file are
// regenerated in place and the remaining findings are returned; otherwise stale blocks are
// findings. Load errors, including code that does not compile, are returned as errors.
func Run(opts Options) ([]Finding, error) {
	w, err := Load(opts.Root, opts.Env, opts.Modules...)
	if err != nil {
		return nil, err
	}
	var out []Finding
	if opts.Docs {
		files, err := DocFiles(opts.Root)
		if err != nil {
			return nil, err
		}
		for _, rel := range files {
			path := filepath.Join(opts.Root, filepath.FromSlash(rel))
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, errors.Join(errors.New("doclint: read "+rel), err)
			}
			updated, f := ScanMarkdown(w, rel, string(data), opts.Write)
			out = append(out, f...)
			if opts.Write && updated != string(data) {
				if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
					return nil, errors.Join(errors.New("doclint: write "+rel), err)
				}
			}
		}
	}
	if opts.Comments {
		out = append(out, ScanCode(w, opts.Legacy)...)
	}
	return out, nil
}

// Main is the doclint command: it parses args, prints findings to stdout and returns the exit
// code (0 clean, 1 findings, 2 usage or load error). Without -root it uses the nearest directory
// above the working directory that holds go.work, so it works from tools/ as `go run ./doclint`.
func Main(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("doclint", flag.ContinueOnError)
	fl.SetOutput(stderr)
	root := fl.String("root", "", "repository root holding go.work (default: nearest parent of the working directory holding go.work)")
	docs := fl.Bool("docs", false, "scan README.md, SECURITY.md, CONTRIBUTING.md, llms.txt, .llms/** and docs/**")
	code := fl.Bool("code", false, "scan exported doc comments of non-legacy packages")
	write := fl.Bool("write", false, "regenerate embedded example blocks in place")
	check := fl.Bool("check", false, "report stale embedded example blocks (default)")
	modules := fl.String("modules", strings.Join(archtest.WorkspaceModules, ","), "comma-separated module directories, relative to -root, loaded one by one")
	legacy := fl.String("legacy", strings.Join(DefaultLegacyDirs(), ","), "comma-separated legacy directories skipped by -code")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr, "doclint: unexpected arguments:", strings.Join(fl.Args(), " "))
		return 2
	}
	if *write && *check {
		_, _ = fmt.Fprintln(stderr, "doclint: -write and -check are mutually exclusive")
		return 2
	}
	if !*docs && !*code {
		*docs, *code = true, true
	}
	dir := *root
	if dir == "" {
		found, err := archtest.FindRepoRoot()
		if err != nil {
			_, _ = fmt.Fprintln(stderr, errors.Join(errors.New("doclint: no -root given"), err))
			return 2
		}
		dir = found
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, errors.Join(errors.New("doclint: resolve -root"), err))
		return 2
	}
	gowork := filepath.Join(abs, "go.work")
	if _, err := os.Stat(gowork); err != nil {
		_, _ = fmt.Fprintln(stderr, errors.Join(errors.New("doclint: "+abs+" holds no go.work"), err))
		return 2
	}
	findings, err := Run(Options{
		Root:     abs,
		Docs:     *docs,
		Comments: *code,
		Write:    *write,
		Legacy:   splitList(*legacy),
		Modules:  splitList(*modules),
		Env:      []string{"GOWORK=" + gowork},
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	for _, f := range findings {
		_, _ = fmt.Fprintln(stdout, f)
	}
	if len(findings) > 0 {
		return 1
	}
	return 0
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
