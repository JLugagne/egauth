package hashertest_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/JLugagne/egauth/passwords/hashertest"
)

type recorder struct {
	testing.TB
	failures []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

func TestAnUndefinedMockFunctionFailsTheTest(t *testing.T) {
	r := &recorder{TB: t}
	m := &hashertest.MockHasher{T: r}
	if _, err := m.Hash(context.Background(), "pw"); !errors.Is(err, hashertest.ErrUndefined) {
		t.Fatalf("Hash = %v, want ErrUndefined", err)
	}
	if err := m.Compare(context.Background(), "phc", "pw"); !errors.Is(err, hashertest.ErrUndefined) {
		t.Fatalf("Compare = %v, want ErrUndefined", err)
	}
	if len(r.failures) != 2 {
		t.Fatalf("failures = %v, want one per undefined call: a mock must never let a test pass silently", r.failures)
	}
}
