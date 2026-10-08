package archtest_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

func TestG07aReachesEveryExportedName(t *testing.T) {
	ws, cfg := fixture(t, "g07")
	assertFires(t, archtest.CheckG07a(ws, cfg),
		[]string{
			g07 + ".Nested.Opts.AllowHTTP", g07 + ".Options.SkipCSRF", g07 + ".options.DisableRateLimit",
			g07 + "/internal/x.Knobs.TrustProxy",
		},
		[]string{g07 + ".hidden.SkipHidden", g07 + ".Holder.Insecure"})
}

func TestG07aHomeAndEventAcceptancesAreNarrow(t *testing.T) {
	ws, cfg := fixture(t, "g07")
	assertFires(t, archtest.CheckG07a(ws, cfg), []string{g07 + ".Holder.SkipAll", g07 + ".SkipEvent"}, nil)
}
