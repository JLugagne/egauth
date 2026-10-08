package archtest_test

import (
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

func TestG12SeesRawUserKeysAndStreamedRecords(t *testing.T) {
	ws, cfg := fixture(t, "g12")
	got := map[string]string{}
	for _, v := range archtest.CheckG12(ws, cfg) {
		got[v.Symbols[0]] += v.Msg + "\n"
	}
	for sym, wants := range map[string][]string{
		g12 + "/rawuser.Store": {"store.Reaper", "DeleteForSubject"},
		g12 + "/chans.Store":   {"store.Reaper", "DeleteForSubject"},
	} {
		for _, w := range wants {
			if !strings.Contains(got[sym], w) {
				t.Errorf("%s: missing %q in %q", sym, w, got[sym])
			}
		}
	}
}

func TestG12RecognisesOtherUserKeys(t *testing.T) {
	ws, cfg := fixture(t, "g12")
	got := map[string]string{}
	for _, v := range archtest.CheckG12(ws, cfg) {
		got[v.Symbols[0]] += v.Msg + "\n"
	}
	for _, sym := range []string{g12 + "/account.Store", g12 + "/owned.Store"} {
		if !strings.Contains(got[sym], "DeleteForSubject") {
			t.Errorf("%s is user-scoped and must require an erase method: %q", sym, got[sym])
		}
	}
	for _, sym := range []string{g12 + "/good.Store", g12 + "/erasing.Store", g12 + "/nested.Store"} {
		if got[sym] != "" {
			t.Errorf("%s must stay clean: %q", sym, got[sym])
		}
	}
}

func TestG12FollowsRecordsOfOtherPackagesAndUnnamedParameters(t *testing.T) {
	ws, cfg := fixture(t, "g12")
	got := map[string]string{}
	for _, v := range archtest.CheckG12(ws, cfg) {
		got[v.Symbols[0]] += v.Msg + "\n"
	}
	for sym, wants := range map[string][]string{
		g12 + "/foreign.Store": {"store.Reaper", "DeleteForSubject"},
		g12 + "/unnamed.Store": {"unnamed parameter"},
	} {
		for _, w := range wants {
			if !strings.Contains(got[sym], w) {
				t.Errorf("%s: missing %q in %q", sym, w, got[sym])
			}
		}
	}
	if s := got[g12+"/foreignok.Store"]; s != "" {
		t.Errorf("foreignok.Store must stay clean: %q", s)
	}
}
