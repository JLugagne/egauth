package event_test

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/event"
)

func typedConsts(t *testing.T) (declared map[string]bool, cases map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
	cfg := types.Config{Importer: importer.Default(), Error: func(error) {}}
	pkg, _ := cfg.Check("github.com/JLugagne/egauth/event", fset, files, info)
	typeName, ok := pkg.Scope().Lookup("Type").(*types.TypeName)
	if !ok {
		t.Fatal("event.Type not found")
	}
	declared, cases = map[string]bool{}, map[string]bool{}
	for _, name := range pkg.Scope().Names() {
		if c, ok := pkg.Scope().Lookup(name).(*types.Const); ok && types.Identical(c.Type(), typeName.Type()) {
			declared[name] = true
		}
	}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name.Name != "Severity" {
				continue
			}
			fn, ok := info.Defs[fd.Name].(*types.Func)
			if !ok {
				continue
			}
			recv := fn.Type().(*types.Signature).Recv().Type()
			if !types.Identical(recv, typeName.Type()) {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				cc, ok := n.(*ast.CaseClause)
				if !ok {
					return true
				}
				for _, e := range cc.List {
					id, ok := e.(*ast.Ident)
					if !ok {
						t.Errorf("Type.Severity case %T is not a declared constant", e)
						continue
					}
					c, ok := info.Uses[id].(*types.Const)
					if !ok || !types.Identical(c.Type(), typeName.Type()) {
						t.Errorf("Type.Severity case %s is not an event.Type constant", id.Name)
						continue
					}
					cases[c.Name()] = true
				}
				return true
			})
		}
	}
	return declared, cases
}

func TestSeverityCoversEveryDeclaredType(t *testing.T) {
	declared, cases := typedConsts(t)
	if len(declared) < 40 {
		t.Fatalf("only %d Type constants found; the scan is broken", len(declared))
	}
	for name := range declared {
		if !cases[name] {
			t.Errorf("event.%s has no case in Type.Severity", name)
		}
	}
	for name := range cases {
		if !declared[name] {
			t.Errorf("Type.Severity switches on unknown %s", name)
		}
	}
}

func TestSeverityValues(t *testing.T) {
	for typ, want := range map[event.Type]event.Severity{
		event.LoginSucceeded:        event.SeverityInfo,
		event.CredentialAdded:       event.SeverityInfo,
		event.IdentifierChanged:     event.SeverityInfo,
		event.LoginFailed:           event.SeverityWarn,
		event.SystemCallerUsed:      event.SeverityWarn,
		event.InsecureConfiguration: event.SeverityWarn,
		event.RefreshReuseDetected:  event.SeverityWarn,
		event.MountMismatch:         event.SeverityError,
		event.RevocationUnavailable: event.SeverityError,
		event.Type("unknown"):       event.SeverityError,
	} {
		if got := typ.Severity(); got != want {
			t.Errorf("%s: severity %s, want %s", typ, got, want)
		}
	}
	if event.Severity(0).String() != "invalid" || event.SeverityWarn.String() != "warn" {
		t.Fatal("unexpected severity names")
	}
}

func TestPublicAttrsDropsEverythingButPublic(t *testing.T) {
	e := event.Event{Type: event.LoginFailed, Attrs: map[string]any{
		string(event.KeyMethod):       "password",
		string(event.KeyIP):           "192.0.2.1",
		string(event.KeyCaptchaToken): "tok-secret",
		"custom":                      "x",
	}}
	got := e.PublicAttrs()
	if len(got) != 1 || got[string(event.KeyMethod)] != "password" {
		t.Fatalf("PublicAttrs = %v", got)
	}
	if len(e.Attrs) != 4 {
		t.Fatal("PublicAttrs must not mutate the event")
	}
	if (event.Event{}).PublicAttrs() != nil {
		t.Fatal("no attributes must yield nil")
	}
}

func leakyEvent() event.Event {
	return event.Event{Type: event.LoginFailed, Attrs: map[string]any{
		string(event.KeyMethod):       "password",
		string(event.KeyIP):           "192.0.2.1",
		string(event.KeyCaptchaToken): "tok-secret",
		"custom":                      "custom-value",
	}}
}

func assertNoLeak(t *testing.T, out string) {
	t.Helper()
	for _, bad := range []string{"tok-secret", "captcha_token", "192.0.2.1", "custom-value"} {
		if strings.Contains(out, bad) {
			t.Errorf("output leaks %q: %s", bad, out)
		}
	}
	if !strings.Contains(out, "password") {
		t.Errorf("public attribute missing: %s", out)
	}
}

func TestSlogSinkNeverPrintsNonPublicAttributes(t *testing.T) {
	var buf bytes.Buffer
	event.NewSlogSink(slog.New(slog.NewJSONHandler(&buf, nil))).EmitEvent(context.Background(), leakyEvent())
	assertNoLeak(t, buf.String())
}

func TestMultiSinkHandsMembersPublicAttributesOnly(t *testing.T) {
	var got event.Event
	sink := event.MultiSink(event.SinkFunc(func(_ context.Context, e event.Event) { got = e }))
	sink.EmitEvent(context.Background(), leakyEvent())
	if len(got.Attrs) != 1 || got.Attrs[string(event.KeyMethod)] != "password" {
		t.Fatalf("member saw %v", got.Attrs)
	}
}

func TestDiscardDropsEvents(t *testing.T) {
	event.Discard.EmitEvent(context.Background(), leakyEvent())
	event.Emit(context.Background(), event.Discard, leakyEvent())
}

func TestSlogLevelFollowsSeverity(t *testing.T) {
	for typ, want := range map[event.Type]string{
		event.LoginSucceeded: "INFO", event.SystemCallerUsed: "WARN", event.MountMismatch: "ERROR",
	} {
		var buf bytes.Buffer
		event.NewSlogSink(slog.New(slog.NewJSONHandler(&buf, nil))).EmitEvent(context.Background(), event.Event{Type: typ})
		if !strings.Contains(buf.String(), `"level":"`+want+`"`) {
			t.Errorf("%s: %s", typ, buf.String())
		}
	}
}

func TestSlogSinkOmitsEnvelopePII(t *testing.T) {
	var buf bytes.Buffer
	event.NewSlogSink(slog.New(slog.NewJSONHandler(&buf, nil))).EmitEvent(context.Background(), event.Event{
		Type: event.DeliveryFailed, TenantID: "tenant-1", UserID: "user-4f2a", Reason: "smtp_rejected",
		Err: event.CauseOf(errors.New("550 mailbox jane@example.com unavailable")),
	})
	out := buf.String()
	for _, bad := range []string{"user-4f2a", "jane@example.com", "mailbox"} {
		if strings.Contains(out, bad) {
			t.Errorf("slog output leaks %q: %s", bad, out)
		}
	}
	for _, want := range []string{"tenant-1", "smtp_rejected", `"level":"ERROR"`, "error_type"} {
		if !strings.Contains(out, want) {
			t.Errorf("slog output misses %q: %s", want, out)
		}
	}
}

func TestAttrsUpToNeverReturnsSecrets(t *testing.T) {
	e := leakyEvent()
	for limit, want := range map[event.Sensitivity][]event.AttrKey{
		event.Sensitivity(0): nil,
		event.Public:         {event.KeyMethod},
		event.PII:            {event.KeyMethod, event.KeyIP},
		event.Secret:         {event.KeyMethod, event.KeyIP},
	} {
		got := e.AttrsUpTo(limit)
		if len(got) != len(want) {
			t.Errorf("%s: AttrsUpTo = %v", limit, got)
			continue
		}
		for _, k := range want {
			if _, ok := got[string(k)]; !ok {
				t.Errorf("%s: missing %s in %v", limit, k, got)
			}
		}
	}
}

func TestDiscardIsAZeroSizeSink(t *testing.T) {
	var s event.Sink = event.Discard
	if _, ok := s.(event.DiscardSink); !ok {
		t.Fatal("Discard must be a DiscardSink")
	}
}
