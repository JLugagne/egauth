package passkeysvc_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
)

type descriptor struct {
	id         string
	transports string
}

func descriptors(t *testing.T, w *world, identifier string) []descriptor {
	t.Helper()
	c, _ := w.beginLogin(map[string]any{routes.FieldIdentifier: identifier})
	list, _ := publicKeyOf(t, c.Options)["allowCredentials"].([]any)
	out := make([]descriptor, 0, len(list))
	for _, d := range list {
		m, _ := d.(map[string]any)
		id, _ := m["id"].(string)
		var ts []string
		raw, _ := m["transports"].([]any)
		for _, tr := range raw {
			s, _ := tr.(string)
			ts = append(ts, s)
		}
		out = append(out, descriptor{id: id, transports: strings.Join(ts, ",")})
	}
	return out
}

func TestDecoyShapesSpanRealAccountShapes(t *testing.T) {
	w := newWorld(t)
	counts, lengths, transports := map[int]bool{}, map[int]bool{}, map[string]bool{}
	for i := range 400 {
		ds := descriptors(t, w, fmt.Sprintf("ghost%d@example.com", i))
		counts[len(ds)] = true
		for _, d := range ds {
			raw, err := base64.RawURLEncoding.DecodeString(d.id)
			if err != nil {
				t.Fatal(err)
			}
			lengths[len(raw)] = true
			transports[d.transports] = true
		}
	}
	for _, n := range []int{1, 2, 3} {
		if !counts[n] {
			t.Errorf("no decoy lists %d credentials: %v", n, counts)
		}
	}
	for _, n := range []int{16, 20, 32, 64} {
		if !lengths[n] {
			t.Errorf("no decoy credential id is %d bytes: %v", n, lengths)
		}
	}
	if len(transports) < 3 || !slices.ContainsFunc(keys(transports), func(s string) bool { return strings.Contains(s, "usb") }) {
		t.Errorf("decoy transports are a fixed fingerprint: %v", transports)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestUsernameFirstBeginReadsTheSameStoresForEveryIdentifier(t *testing.T) {
	w := newWorld(t)
	w.enrolled("alice@example.com")
	w.user("nopasskey@example.com")
	disabled, _ := w.enrolled("disabled@example.com")
	if _, err := w.identity.Apply(context.Background(), identity.SetDisabledState{Subject: disabled, Disable: true}); err != nil {
		t.Fatal(err)
	}
	type reads struct{ state, lists int64 }
	measure := func(identifier string) reads {
		s, l := w.stateReads.Load(), w.hooks.lists.Load()
		descriptors(t, w, identifier)
		return reads{w.stateReads.Load() - s, w.hooks.lists.Load() - l}
	}
	want := measure("alice@example.com")
	if want.state == 0 || want.lists == 0 {
		t.Fatalf("a real account read %+v", want)
	}
	for _, id := range []string{"ghost@example.com", "nopasskey@example.com", "disabled@example.com"} {
		if got := measure(id); got != want {
			t.Errorf("%s read %+v, a real account %+v", id, got, want)
		}
	}
}
