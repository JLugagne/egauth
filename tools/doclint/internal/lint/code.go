package lint

import (
	"cmp"
	"go/ast"
	"go/token"
	"slices"
	"strings"

	"github.com/JLugagne/egauth/tools/archtest"
)

// DefaultLegacyDirs returns the repository-relative directories of the packages slated for
// deletion by the rewrite, whose doc comments -code skips. It is derived from the archtest legacy
// registry so both guards shrink together.
func DefaultLegacyDirs() []string {
	return archtest.LegacyRelPrefixes()
}

// ScanCode applies G26 to the package docs and to every doc or line comment attached to an
// exported declaration (declaration groups, struct fields and interface methods included) of the
// non-test files of the loaded modules, skipping files under any of the legacy directories.
func ScanCode(w *Workspace, legacy []string) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, p := range w.roots {
		for _, f := range p.Syntax {
			pos := p.Fset.Position(f.Pos())
			if strings.HasSuffix(pos.Filename, "_test.go") || seen[pos.Filename] {
				continue
			}
			seen[pos.Filename] = true
			rel := relPath(w.root, pos.Filename)
			if isLegacy(rel, legacy) {
				continue
			}
			out = append(out, scanFileDocs(w, rel, p.Fset, f)...)
		}
	}
	slices.SortStableFunc(out, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line))
	})
	return out
}

func isLegacy(rel string, legacy []string) bool {
	for _, d := range legacy {
		if d != "" && (rel == d || strings.HasPrefix(rel, d+"/")) {
			return true
		}
	}
	return false
}

func scanFileDocs(w *Workspace, rel string, fset *token.FileSet, f *ast.File) []Finding {
	var out []Finding
	done := map[*ast.CommentGroup]bool{}
	emit := func(groups ...*ast.CommentGroup) {
		for _, cg := range groups {
			if cg == nil || done[cg] {
				continue
			}
			done[cg] = true
			out = append(out, ScanText(w, rel, fset.Position(cg.Pos()).Line, commentLines(cg))...)
		}
	}
	emit(f.Doc)
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Name.IsExported() {
				emit(d.Doc)
			}
		case *ast.GenDecl:
			if d.Tok == token.IMPORT {
				continue
			}
			exported := false
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() {
						exported = true
						emit(s.Doc, s.Comment)
						emitMembers(s.Type, emit)
					}
				case *ast.ValueSpec:
					if anyExported(s.Names) {
						exported = true
						emit(s.Doc, s.Comment)
					}
				}
			}
			if exported {
				emit(d.Doc)
			}
		}
	}
	return out
}

func emitMembers(typ ast.Expr, emit func(...*ast.CommentGroup)) {
	ast.Inspect(typ, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncType:
			return false
		case *ast.Field:
			if len(n.Names) == 0 || anyExported(n.Names) {
				emit(n.Doc, n.Comment)
				return true
			}
			return false
		}
		return true
	})
}

func anyExported(ids []*ast.Ident) bool {
	for _, id := range ids {
		if id.IsExported() {
			return true
		}
	}
	return false
}

func commentLines(cg *ast.CommentGroup) []string {
	var out []string
	for _, c := range cg.List {
		if line, ok := strings.CutPrefix(c.Text, "//"); ok {
			out = append(out, line)
			continue
		}
		for _, l := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(c.Text, "/*"), "*/"), "\n") {
			t := strings.TrimLeft(l, " \t")
			if strings.HasPrefix(t, "*") {
				l = t[1:]
			}
			out = append(out, l)
		}
	}
	return out
}
