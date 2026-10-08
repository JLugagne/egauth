package mfa_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/mfa"
)

var (
	_ func(mfa.Store, context.Context, principal.Subject) (bool, error)                        = mfa.Store.HasConfirmedTOTP
	_ func(mfa.Store, context.Context) (bool, error)                                           = mfa.Store.AnyEnrolled
	_ func(mfa.Store, context.Context) (int64, error)                                          = mfa.Store.CountEnrolled
	_ func(mfa.Store, context.Context, principal.Subject, int64) (bool, error)                 = mfa.Store.MarkTOTPUsed
	_ func(mfa.Store, context.Context, mfa.Lockout) (int, error)                               = mfa.Store.IncrementTOTPAttempts
	_ func(mfa.Store, context.Context, mfa.Lockout) (int, error)                               = mfa.Store.IncrementRecoveryAttempts
	_ func(mfa.Store, context.Context, mfa.Reseal) (bool, error)                               = mfa.Store.ReplaceSealed
	_ func(mfa.Store, context.Context, store.Cursor, int) ([]mfa.V016Row, store.Cursor, error) = mfa.Store.V016Sealed
	_ func(mfa.Store, context.Context) (int64, error)                                          = mfa.Store.CountLegacySealed
)

func TestStoreMandatesLockoutsAndBase(t *testing.T) {
	st := reflect.TypeFor[mfa.Store]()
	for _, name := range []string{"Ping", "EraseTenant", "Durability", "DeleteForSubject", "ResetTOTPAttempts", "ResetRecoveryAttempts"} {
		if _, ok := st.MethodByName(name); !ok {
			t.Fatalf("mfa.Store lacks %s", name)
		}
	}
}

func TestEnrollmentConfirmed(t *testing.T) {
	now := time.Now()
	if (mfa.Enrollment{}).Confirmed() || !(mfa.Enrollment{ConfirmedAt: &now}).Confirmed() {
		t.Fatal("Confirmed must follow ConfirmedAt")
	}
}

func TestResealComparesTheSealedBytesRead(t *testing.T) {
	r := reflect.TypeFor[mfa.Reseal]()
	for _, name := range []string{"Old", "New"} {
		f, ok := r.FieldByName(name)
		if !ok || f.Type != reflect.TypeFor[[]byte]() {
			t.Fatalf("Reseal lacks the sealed bytes %s: a re-seal must CAS on the bytes it read", name)
		}
	}
	if f, ok := r.FieldByName("Ref"); !ok || f.Type != reflect.TypeFor[mfa.SealedRef]() {
		t.Fatal("Reseal must address its row")
	}
}

func TestStartupEnrollmentCheckIsDeploymentWide(t *testing.T) {
	st := reflect.TypeFor[mfa.Store]()
	for _, name := range []string{"AnyEnrolled", "CountEnrolled"} {
		m, ok := st.MethodByName(name)
		if !ok || m.Type.NumIn() != 1 {
			t.Fatalf("%s must take only a context: New has no subject to ask about (C-01)", name)
		}
	}
}

func TestFreshWritesRefuseLegacyAADVersion(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "store.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Store" {
			return true
		}
		for _, m := range ts.Type.(*ast.InterfaceType).Methods.List {
			if len(m.Names) == 1 {
				docs[m.Names[0].Name] = m.Doc.Text()
			}
		}
		return false
	})
	for _, name := range []string{"SaveTOTP", "ConfirmEnrollment"} {
		if !strings.Contains(docs[name], "ErrLegacyAADVersion") {
			t.Fatalf("%s writes a sealed secret but accepts AADVersionLegacy: startup would then refuse (C-58)", name)
		}
	}
	if !strings.Contains(docs["V016Sealed"], "LegacySealed(cursor)") {
		t.Fatal("V016Sealed must record its DESIGN name LegacySealed(cursor)")
	}
	if mfa.ErrLegacyAADVersion == nil {
		t.Fatal("ErrLegacyAADVersion must be declared")
	}
}
