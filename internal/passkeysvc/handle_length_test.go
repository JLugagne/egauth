package passkeysvc_test

import (
	"testing"

	"github.com/JLugagne/egauth/internal/routes"
)

func TestLoginBeginHandleLengthIsIndependentOfTheAccount(t *testing.T) {
	w := newWorld(t)
	w.enrolled("alice@example.com")
	w.user("nopasskey@example.com")
	lengths := map[string]map[int]int{}
	for range 200 {
		for _, id := range []string{"alice@example.com", "nopasskey@example.com", "ghost@example.com", ""} {
			fields := map[string]any{}
			if id != "" {
				fields[routes.FieldIdentifier] = id
			}
			c, _ := w.beginLogin(fields)
			kind := "username-first"
			if id == "" {
				kind = "discoverable"
			}
			if lengths[kind] == nil {
				lengths[kind] = map[int]int{}
			}
			lengths[kind][len(c.Handle)]++
		}
	}
	for kind, seen := range lengths {
		if len(seen) != 1 {
			t.Errorf("%s handle lengths vary (length: count): %v", kind, seen)
		}
	}
}
