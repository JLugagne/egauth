package archtest

import (
	"go/ast"
	"go/token"
	"go/types"
	"path"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// G15 enforces the import layering of DESIGN.md section 2.1.
const G15 GuardID = "G15"

var rootImporters = []string{"memstore", "egauthtest", "internal/journeytest", "examples"}

// RootImportAllowances returns the package prefixes, relative to the root package, that DESIGN.md
// section 2.1 allows to import the root package from non-test code. The set is fixed by the spec
// and pinned by a test; it is not an exemption list.
func RootImportAllowances() []string {
	return slices.Clone(rootImporters)
}

var harnessImporters = map[string][]string{"internal/journeytest": {"egauthtest", "memstore", "webauthntest"}}

// HarnessImportAllowances returns, per package prefix relative to the root package, the higher
// layers that the behavioural harness of DESIGN.md section 9.4 may import from non-test code: its
// exported RunAgainst is called from other packages' tests, so it cannot live in a _test.go file,
// and its drivers run PasskeyDiscoverable through the webauthntest authenticator.
// The set is fixed by the spec and pinned by a test; it is not an exemption list.
func HarnessImportAllowances() map[string][]string {
	out := make(map[string][]string, len(harnessImporters))
	for k, v := range harnessImporters {
		out[k] = slices.Clone(v)
	}
	return out
}

type leafLayer struct {
	prefix  string
	allowed []string
}

var leafLayers = []leafLayer{
	{prefix: "internal/core", allowed: []string{"internal/core", "internal/redirect"}},
	{prefix: "internal/redirect", allowed: []string{"internal/redirect"}},
	{prefix: "internal/clock", allowed: []string{"internal/clock"}},
	{prefix: "kek", allowed: []string{"kek"}},
	{prefix: "signing", allowed: []string{"signing"}},
	{prefix: "principal", allowed: []string{"principal", "internal/core"}},
	{prefix: "event", allowed: []string{"event", "principal"}},
}

var higherLayers = []string{"memstore", "examples", "adapters", "tools"}

var storeRootAllowed = []string{"principal", "event"}

var storeContractAllowed = []string{"store", "principal", "event"}

var storeImplAllowed = []string{"store", "principal", "event", "kek", "signing", "internal/clock"}

var memstoreAllowed = []string{"memstore", "principal", "event", "kek", "signing"}

var storeTestForbidden = []string{"memstore", "adapters", "egauthtest"}

var pgxAllowed = []string{"", "store", "kek", "principal", "event"}

var otelAllowed = []string{"event", "principal"}

var coreStdlib = []string{
	"time", "encoding/binary", "errors", "strings", "bytes", "slices", "maps", "math",
	"math/bits", "sort", "strconv", "unicode", "unicode/utf8",
}

var coreRestrictedStdlib = map[string][]string{
	"fmt": {"Sprintf", "Sprint", "Sprintln", "Append", "Appendf", "Appendln", "Stringer", "GoStringer", "Formatter", "State"},
	"log/slog": {
		"Value", "Attr", "LogValuer", "Kind", "GroupValue", "AnyValue", "StringValue", "IntValue",
		"Int64Value", "Uint64Value", "Float64Value", "BoolValue", "DurationValue", "TimeValue", "String",
		"Int", "Int64", "Uint64", "Float64", "Bool", "Duration", "Time", "Any", "Group", "KindAny",
		"KindBool", "KindDuration", "KindFloat64", "KindInt64", "KindString", "KindTime", "KindUint64",
		"KindGroup", "KindLogValuer",
	},
}

// CheckG15 rejects import layering violations: leaf layers (internal/core, internal/redirect,
// internal/clock, kek, signing, principal, event, subpackages included) and store contracts
// importing upwards; the root package and internal/* importing a higher layer (memstore, examples,
// adapters, tools, store implementations such as store/<x>/memory or store/<x>/storetest, and
// public test helpers such as webauthntest); store implementations (store/<x>/<impl>) importing
// more than store packages, principal, event, kek, signing and internal/clock; storetest packages
// importing memstore, adapters or egauthtest; internal/core importing anything outside uuid, time,
// crypto/*, encoding/binary and pure standard helpers, or using fmt or log/slog beyond their pure
// formatting and value constructors; any adapter importing root internal packages; adapters/pgx
// importing more than the root, store contracts, kek, principal and event; adapters/otel importing
// more than event and principal; memstore importing more than the root, store contracts,
// store/<x>/memory, principal, event, kek and signing; egauthtest importing a higher layer such as
// memstore; any non-test import of egauthtest; any non-test import of internal/journeytest from
// outside it; and any non-test import of the root package by core-module packages other than
// RootImportAllowances. HarnessImportAllowances
// are the only importers spared the egauthtest and higher-layer rules.
func CheckG15(ws *Workspace, cfg Config) []Violation {
	var out []Violation
	ws.eachFile(true, func(pkg *packages.Package, file *ast.File, filename string) {
		test := isTestFile(filename)
		importerRel, inRoot := cfg.Rel(pkg.PkgPath)
		if !inRoot {
			return
		}
		adapter := cfg.isAdapter(pkg.PkgPath)
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			report := func(msg string) {
				out = append(out, Violation{Guard: G15, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, spec.Pos()), Symbols: []string{pkg.PkgPath}, Msg: pkg.PkgPath + " imports " + path + ": " + msg})
			}
			rel, ok := cfg.Rel(path)
			if !ok {
				if !test && within(importerRel, "internal/core") {
					out = append(out, coreExternalViolations(ws, cfg, pkg, file, spec, path)...)
				}
				continue
			}
			isInternal := within(rel, "internal")
			if !test && within(rel, "egauthtest") && !harnessImportAllowed(importerRel, rel) {
				report("non-test import of egauthtest")
			}
			if !test && within(rel, "internal/journeytest") && !within(importerRel, "internal/journeytest") {
				report("non-test import of internal/journeytest")
			}
			if adapter {
				if isInternal {
					report("adapter imports a root internal package")
				}
				if test {
					continue
				}
				if within(importerRel, "adapters/otel") && !allowedPrefix(rel, otelAllowed) && !within(rel, "adapters/otel") {
					report("adapters/otel may import only event and principal")
				}
				if within(importerRel, "adapters/pgx") && !pgxImportAllowed(rel) {
					report("adapters/pgx may import only the root, store contracts, kek, principal and event")
				}
				continue
			}
			if rel == "" && !test && !rootImportAllowed(importerRel) {
				report("core-module package imports the root package")
			}
			if test {
				continue
			}
			if msg := layerViolation(importerRel, rel); msg != "" {
				report(msg)
			}
		}
	})
	return dedupe(out)
}

func layerViolation(importerRel, rel string) string {
	for _, l := range leafLayers {
		if within(importerRel, l.prefix) && !allowedPrefix(rel, l.allowed) {
			return "layer " + l.prefix + " may import only " + strings.Join(l.allowed, ", ")
		}
	}
	switch {
	case importerRel == "":
		if isHigherLayer(rel) {
			return "the root package may import only internal/* and contracts"
		}
	case within(importerRel, "memstore"):
		if !memstoreImportAllowed(rel) {
			return "memstore may import only the root, store contracts, store/<x>/memory, " + strings.Join(memstoreAllowed, ", ")
		}
	case within(importerRel, "egauthtest"):
		if isHigherLayer(rel) {
			return "egauthtest may import only the root, internal/* and contracts"
		}
	case within(importerRel, "internal"):
		if isHigherLayer(rel) && !harnessImportAllowed(importerRel, rel) {
			return "internal package imports a higher layer"
		}
	case importerRel == "store":
		if !allowedPrefix(rel, storeRootAllowed) {
			return "store may import only " + strings.Join(storeRootAllowed, ", ")
		}
	case isStoreContract(importerRel):
		if !slices.Contains(storeContractAllowed, rel) {
			return "store contract " + importerRel + " may import only " + strings.Join(storeContractAllowed, ", ")
		}
	case isStoreTest(importerRel):
		if allowedPrefix(rel, storeTestForbidden) {
			return "storetest package " + importerRel + " may not import " + strings.Join(storeTestForbidden, ", ")
		}
	case within(importerRel, "store"):
		if !allowedPrefix(rel, storeImplAllowed) {
			return "store implementation " + importerRel + " may import only " + strings.Join(storeImplAllowed, ", ")
		}
	}
	return ""
}

func isHigherLayer(rel string) bool {
	switch {
	case within(rel, "egauthtest"):
		return false
	case allowedPrefix(rel, higherLayers):
		return true
	case within(rel, "store") && rel != "store" && !isStoreContract(rel):
		return true
	}
	return !within(rel, "internal") && rel != "" && strings.HasSuffix(path.Base(rel), "test")
}

func memstoreImportAllowed(rel string) bool {
	if rel == "" || rel == "store" || isStoreContract(rel) || allowedPrefix(rel, memstoreAllowed) {
		return true
	}
	parts := strings.Split(rel, "/")
	return len(parts) == 3 && parts[0] == "store" && parts[2] == "memory"
}

func harnessImportAllowed(importerRel, rel string) bool {
	for prefix, targets := range harnessImporters {
		if within(importerRel, prefix) && allowedPrefix(rel, targets) {
			return true
		}
	}
	return false
}

func isStoreTest(rel string) bool {
	parts := strings.Split(rel, "/")
	return len(parts) >= 3 && parts[0] == "store" && parts[2] == "storetest"
}

func coreExternalViolations(ws *Workspace, cfg Config, pkg *packages.Package, file *ast.File, spec *ast.ImportSpec, path string) []Violation {
	if coreExternalAllowed(cfg, path) {
		return nil
	}
	newViolation := func(pos token.Pos, sym, msg string) Violation {
		return Violation{Guard: G15, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, pos), Symbols: []string{pkg.PkgPath, sym}, Msg: msg}
	}
	allowedNames, restricted := coreRestrictedStdlib[path]
	if !restricted || spec.Name != nil && (spec.Name.Name == "_" || spec.Name.Name == ".") {
		return []Violation{newViolation(spec.Pos(), pkg.PkgPath, pkg.PkgPath+" imports "+path+": internal/core is a leaf: only uuid, time, crypto/*, encoding/binary and pure standard helpers")}
	}
	var out []Violation
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pn, ok := pkg.TypesInfo.Uses[id].(*types.PkgName)
		if !ok || pn.Imported().Path() != path || slices.Contains(allowedNames, sel.Sel.Name) {
			return true
		}
		out = append(out, newViolation(sel.Pos(), enclosingSymbol(pkg, file, sel.Pos()), pkg.PkgPath+" uses "+path+"."+sel.Sel.Name+": internal/core may use "+path+" only for pure formatting and values"))
		return true
	})
	return out
}

func within(rel, prefix string) bool {
	return rel == prefix || strings.HasPrefix(rel, prefix+"/")
}

func allowedPrefix(rel string, allowed []string) bool {
	return slices.ContainsFunc(allowed, func(a string) bool { return within(rel, a) })
}

func isStoreContract(rel string) bool {
	rest, ok := strings.CutPrefix(rel, "store/")
	return ok && rest != "" && !strings.Contains(rest, "/")
}

func pgxImportAllowed(rel string) bool {
	return slices.Contains(pgxAllowed, rel) || isStoreContract(rel) || within(rel, "adapters/pgx")
}

func coreExternalAllowed(cfg Config, path string) bool {
	return path == cfg.uuidPath() || within(path, "crypto") || slices.Contains(coreStdlib, path)
}

func rootImportAllowed(importerRel string) bool {
	return slices.ContainsFunc(rootImporters, func(a string) bool { return within(importerRel, a) })
}

// CheckRootImportAllowances reports every RootImportAllowances prefix that matches no loaded
// package. It is enforced at release so that a renamed or deleted importer cannot leave a silent
// allowance behind.
func CheckRootImportAllowances(ws *Workspace, cfg Config) []string {
	var out []string
	for _, a := range rootImporters {
		if ws.ResolveSymbol(cfg.path(a)+"/...") != nil {
			out = append(out, "G15: root import allowance "+a+" matches no package")
		}
	}
	return out
}
