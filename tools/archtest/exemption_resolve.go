package archtest

import (
	"errors"
	"go/types"
	"strings"
)

// ResolveSymbol resolves an exemption symbol through go/types. A bare import path resolves to
// the package, "<path>.<Name>" to a package-level object, and "<path>.<Type>.<Member>" to a
// method or field.
func (w *Workspace) ResolveSymbol(sym string) error {
	if sym == "" {
		return errors.New("empty symbol")
	}
	if prefix, ok := strings.CutSuffix(sym, "/..."); ok {
		for path := range w.byPath {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				return nil
			}
		}
		return errors.New("no package matches prefix " + prefix)
	}
	if w.byPath[sym] != nil {
		return nil
	}
	slash := strings.LastIndex(sym, "/")
	dot := strings.Index(sym[slash+1:], ".")
	if dot < 0 {
		return errors.New("symbol does not resolve: " + sym)
	}
	dot += slash + 1
	pkg := w.byPath[sym[:dot]]
	if pkg == nil {
		return errors.New("package not loaded: " + sym[:dot])
	}
	parts := strings.Split(sym[dot+1:], ".")
	obj := pkg.Types.Scope().Lookup(parts[0])
	if obj == nil {
		return errors.New("no such object: " + sym)
	}
	switch len(parts) {
	case 1:
		return nil
	case 2:
		if _, ok := obj.(*types.TypeName); !ok {
			return errors.New("not a type: " + sym)
		}
		if m, _, _ := types.LookupFieldOrMethod(obj.Type(), true, pkg.Types, parts[1]); m == nil {
			return errors.New("no such member: " + sym)
		}
		return nil
	default:
		return errors.New("symbol has too many segments: " + sym)
	}
}

// HasIdentifier reports whether name is declared anywhere in the workspace's own packages as a
// package-level object, struct field or method. A qualified name is resolved as a symbol.
func (w *Workspace) HasIdentifier(name string) bool {
	if strings.ContainsAny(name, "/.") {
		return w.ResolveSymbol(name) == nil
	}
	for _, pkg := range w.roots() {
		if pkg.Types == nil {
			continue
		}
		scope := pkg.Types.Scope()
		for _, n := range scope.Names() {
			obj := scope.Lookup(n)
			if n == name {
				return true
			}
			tn, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}
			if memberNamed(tn.Type(), name) {
				return true
			}
		}
	}
	return false
}

func memberNamed(t types.Type, name string) bool {
	if st, ok := t.Underlying().(*types.Struct); ok {
		for i := 0; i < st.NumFields(); i++ {
			if st.Field(i).Name() == name {
				return true
			}
		}
	}
	ms := types.NewMethodSet(types.NewPointer(t))
	for i := 0; i < ms.Len(); i++ {
		if ms.At(i).Obj().Name() == name {
			return true
		}
	}
	return false
}
