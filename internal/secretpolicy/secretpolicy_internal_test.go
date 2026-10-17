package secretpolicy

import "testing"

func TestMarkersMatchTheCopiesKeptByKEKAndSigning(t *testing.T) {
	want := []string{"minimum-hs256-signing-secret"}
	if len(markers) != len(want) {
		t.Fatalf("markers = %v; update the publishedMarkers copies in kek/policy.go and signing/policy.go and their parity tests, then this list", markers)
	}
	for i := range want {
		if markers[i] != want[i] {
			t.Fatalf("marker %d = %q, want %q; keep kek and signing in step", i, markers[i], want[i])
		}
	}
}
