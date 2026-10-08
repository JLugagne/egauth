package archtest_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

func g06RowSymbols(t *testing.T) map[string][]string {
	t.Helper()
	ws, cfg := fixture(t, "g06")
	out := map[string][]string{}
	for _, v := range archtest.CheckG06(ws, cfg) {
		row, _, _ := strings.Cut(v.Msg, ":")
		out[row] = append(out[row], v.Symbols...)
	}
	return out
}

func TestG06RegressionsFire(t *testing.T) {
	got := g06RowSymbols(t)
	for row, syms := range map[string][]string{
		"jwt":          {g06 + "/app.JWTSign", g06 + "/app.JWTVerify"},
		"kek":          {g06 + "/app.ConcreteSeal", g06 + "/app.Structural", g06 + "/app.Embedded", g06 + ".Sneaky"},
		"httpx":        {g06 + "/app.AliasedBody", g06 + "/app.LimitedBody"},
		"outbound":     {g06 + "/app.ZeroClient", g06 + "/app.holder"},
		"accountstate": {g06 + "/app.States"},
		"verified":     {g06 + "/app.States"},
		"ctxvalue":     {g06 + ".ActorFromContext"},
	} {
		for _, s := range syms {
			if !slices.Contains(got[row], s) {
				t.Errorf("row %s: expected a finding in %s; got %v", row, s, got[row])
			}
		}
	}
	for _, s := range []string{g06 + "/internal/sealing.Seal", g06 + "/internal/factors.Verified", g06 + "/internal/identitysvc.State", g06 + ".UpgradeSecretsV016"} {
		for row, syms := range got {
			if slices.Contains(syms, s) {
				t.Errorf("owner %s flagged by row %s", s, row)
			}
		}
	}
}

func TestG06TypedExemptionIsBoundToItsRow(t *testing.T) {
	ws, cfg := fixture(t, "g06")
	sawClock := false
	for _, v := range archtest.CheckG06(ws, cfg) {
		if !strings.HasSuffix(v.Pos, "actor.go:9") {
			continue
		}
		sawClock = true
		if strings.HasPrefix(v.Msg, "clock:") && slices.Contains(v.Symbols, g06+".ActorFromContext") {
			t.Errorf("the ctxvalue exemption of ActorFromContext must not cover the clock row: %v", v)
		}
	}
	if !sawClock {
		t.Fatal("time.Now in ActorFromContext must be reported")
	}
}

func TestG06StructuralInterfacesCannotHideOwnedMethods(t *testing.T) {
	got := g06RowSymbols(t)
	b, c := g06+"/structural/b", g06+"/structural/c"
	for row, syms := range map[string][]string{
		"kek":          {b + ".Run", b + ".RunGeneric", b + ".RunSlice", b + ".Back"},
		"ctxvalue":     {c + ".Values", c + ".Asserted"},
		"httpx":        {c + ".Forms"},
		"backendstart": {c + ".Starts", c + ".Switched"},
		"audit":        {c + ".Emits"},
	} {
		for _, s := range syms {
			if !slices.Contains(got[row], s) {
				t.Errorf("row %s: expected a finding in %s; got %v", row, s, got[row])
			}
		}
	}
	for _, s := range []string{b + ".Clean", c + ".Plain", g06 + "/structural/a.Do", g06 + "/structural/a.DoGeneric", g06 + "/internal/sealing.Seal"} {
		for row, syms := range got {
			if slices.Contains(syms, s) {
				t.Errorf("%s flagged by row %s", s, row)
			}
		}
	}
}

func TestG06WrapperTypesCannotHideOwnedMethods(t *testing.T) {
	got := g06RowSymbols(t)
	d := g06 + "/structural/d"
	for row, syms := range map[string][]string{
		"ctxvalue":     {d + ".EmbedCtx", d + ".IfaceEmbed"},
		"kek":          {d + ".EmbedKEK"},
		"backendstart": {d + ".EmbedBackend"},
		"httpx":        {d + ".EmbedReq"},
	} {
		for _, s := range syms {
			if !slices.Contains(got[row], s) {
				t.Errorf("row %s: expected a finding in %s; got %v", row, s, got[row])
			}
		}
	}
	for _, s := range []string{d + ".KeepCtx", d + ".OwnSeal"} {
		for row, syms := range got {
			if slices.Contains(syms, s) {
				t.Errorf("%s flagged by row %s", s, row)
			}
		}
	}
}
