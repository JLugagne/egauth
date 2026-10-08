// Package archtest holds the static architecture guards of the egauth workspace.
package archtest

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"
)

// ModulePath is the import path of the core egauth module and of the root package.
const ModulePath = "github.com/JLugagne/egauth"

// LoadMode is the packages.Load mode shared by every guard. NeedDeps makes dependency types
// resolvable so exemption symbols such as errors.As or net/http.Flusher can be checked.
const LoadMode = packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
	packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax |
	packages.NeedTypesInfo | packages.NeedModule

// WorkspaceModules lists the module directories, relative to the repository root, that are loaded
// one by one.
var WorkspaceModules = []string{".", "adapters/pgx", "adapters/otel"}

// Module is one loaded module: its directory and the packages (test variants included) matched by
// ./... inside it.
type Module struct {
	Dir  string
	Pkgs []*packages.Package
}

// Workspace is the result of loading every module of the repository.
type Workspace struct {
	Root    string
	Modules []Module
	byPath  map[string]*packages.Package
}

// FindRepoRoot walks up from the working directory to the directory holding go.work.
func FindRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", errors.Join(errors.New("archtest: getwd"), err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.work")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("archtest: go.work not found above the working directory")
		}
		dir = parent
	}
}

// LoadWorkspace loads the three workspace modules with the committed go.work, tests included.
// Package-level load errors are returned so that a broken tree never passes a guard silently.
func LoadWorkspace(root string) (*Workspace, error) {
	env := append(os.Environ(), "GOWORK="+filepath.Join(root, "go.work"))
	ws := &Workspace{Root: root}
	for _, rel := range WorkspaceModules {
		dir := filepath.Join(root, rel)
		pkgs, err := loadDir(dir, env, "./...")
		if err != nil {
			return nil, errors.Join(errors.New("archtest: load "+rel), err)
		}
		ws.Modules = append(ws.Modules, Module{Dir: dir, Pkgs: pkgs})
	}
	ws.index()
	return ws, nil
}

// LoadFixture loads fixture packages of the tools module itself (GOWORK=off) as a one-module
// workspace. dir is the tools module directory and patterns are relative package patterns.
func LoadFixture(dir string, patterns ...string) (*Workspace, error) {
	env := append(os.Environ(), "GOWORK=off")
	pkgs, err := loadDir(dir, env, patterns...)
	if err != nil {
		return nil, err
	}
	ws := &Workspace{Root: dir, Modules: []Module{{Dir: dir, Pkgs: pkgs}}}
	ws.index()
	return ws, nil
}

func loadDir(dir string, env []string, patterns ...string) ([]*packages.Package, error) {
	cfg := &packages.Config{Mode: LoadMode, Dir: dir, Env: env, Tests: true}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	var errs []error
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			errs = append(errs, errors.New(p.ID+": "+e.Error()))
		}
	})
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return pkgs, nil
}

func (w *Workspace) index() {
	w.byPath = map[string]*packages.Package{}
	for _, m := range w.Modules {
		packages.Visit(m.Pkgs, nil, func(p *packages.Package) {
			if p.Types == nil {
				return
			}
			cur, ok := w.byPath[p.PkgPath]
			if !ok || (isTestVariant(cur) && !isTestVariant(p)) {
				w.byPath[p.PkgPath] = p
			}
		})
	}
}

func isTestVariant(p *packages.Package) bool { return strings.Contains(p.ID, " [") }

func (w *Workspace) moduleRoots() []string {
	var out []string
	for _, p := range w.roots() {
		if p.Module != nil && !slices.Contains(out, p.Module.Path) {
			out = append(out, p.Module.Path)
		}
	}
	slices.Sort(out)
	return out
}

// Package returns the loaded package with the given import path, dependencies included, or nil.
func (w *Workspace) Package(path string) *packages.Package {
	return w.byPath[path]
}
