package main

import "testing"

// TestDocsCompileCheck runs the identical check `go run ./internal/doctest` performs in CI (see
// the package doc and ci.yml), so a doc-vs-code drift — a fabricated symbol, struct field, or
// method — fails `go test ./...` too, not only the separate CI step. It exercises the real repo
// tree (dir="../../docs/content", root="../..") rather than synthetic fixtures, since the whole
// point is guarding the ACTUAL, currently-published docs against the ACTUAL, currently-built API.
func TestDocsCompileCheck(t *testing.T) {
	failures, resolved, err := run("../../docs/content", "../..", testing.Verbose())
	if err != nil {
		t.Fatalf("doctest: %v", err)
	}
	if failures > 0 {
		t.Errorf("doctest: %d doc reference(s) point at symbols, fields or methods that no "+
			"longer exist. Run `go run ./internal/doctest -v` for the full report, then update "+
			"the docs (or the alias map in internal/doctest) to match the current API.", failures)
	}
	if resolved == 0 {
		t.Fatal("doctest: resolved zero references — the scan itself is broken (empty markdown set or alias map)")
	}
}
