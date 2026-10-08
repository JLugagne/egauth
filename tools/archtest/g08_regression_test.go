package archtest_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

func TestG08ForwardTreatsUnknownVerbsAsWrites(t *testing.T) {
	ws, cfg := fixture(t, "g08")
	assertFires(t, archtest.CheckG08(ws, cfg),
		[]string{g08 + "/store/sessions.TouchRequest", g08 + "/store/sessions.Snapshot", g08 + "/store/tokens.ReissueRequest"},
		[]string{g08 + "/store/tokens.RotationRequest", g08 + "/store/tokens.Filter"})
}

func TestG08InverseReachesPromotedAndNestedFields(t *testing.T) {
	ws, cfg := fixture(t, "g08")
	assertFires(t, archtest.CheckG08(ws, cfg),
		[]string{g08 + "/events.Wrapped.AMR", g08 + "/events.Wrapped.RememberMe", g08 + "/events.Wrapped.Meta.Epoch", g08 + "/events.Options.Factors"},
		nil)
}

func TestG08ForwardReadVerbCompoundsAreWrites(t *testing.T) {
	ws, cfg := fixture(t, "g08")
	assertFires(t, archtest.CheckG08(ws, cfg),
		[]string{g08 + "/store/sessions.Draft", g08 + "/store/sessions.Keyed", g08 + "/store/sessions.Echo"},
		[]string{g08 + "/store/tokens.Filter"})
}

func TestG08ForwardRejectsRawStateAndForeignRecords(t *testing.T) {
	ws, cfg := fixture(t, "g08")
	assertFires(t, archtest.CheckG08(ws, cfg),
		[]string{g08 + "/store/sessions.Compound.StartRaw", g08 + "/ext.Row"},
		[]string{
			g08 + "/store/sessions.Compound.RevocationsSince", g08 + "/store/sessions.Compound.RevokeForSubject",
			g08 + "/store/sessions.Compound.Revoke", g08 + "/store.Cursor", g08 + "/principal.Subject",
		})
}

func TestG08InverseFollowsTheExportedSurface(t *testing.T) {
	ws, cfg := fixture(t, "g08")
	assertFires(t, archtest.CheckG08(ws, cfg),
		[]string{
			g08 + "/exposed.sess.AMR", g08 + "/exposed.sess.RememberMe", g08 + "/internal/opts.Session.AMR",
			g08 + "/exposed.Sessions.Epoch", g08 + "/exposed.Anon.Factors",
		},
		[]string{g08 + "/exposed.quiet.AMR", g08 + "/internal/hidden.Session.AMR"})
}

func TestG08WrapperRecordsCarryNoRawState(t *testing.T) {
	ws, cfg := fixture(t, "g08")
	assertFires(t, archtest.CheckG08(ws, cfg),
		[]string{g08 + "/store/tokens.Wrapper", g08 + "/store/tokens.ScalarWrapper"},
		[]string{g08 + "/store/tokens.RotationRequest", g08 + "/store/tokens.DatedWrapper", g08 + "/store/tokens.RefreshRecord"})
}

func TestG08ReadVerbWithoutResultIsAWrite(t *testing.T) {
	ws, cfg := fixture(t, "g08")
	assertFires(t, archtest.CheckG08(ws, cfg),
		[]string{g08 + "/store/tokens.Ensured", g08 + "/store/tokens.Shapes.ListAppend"},
		[]string{g08 + "/store/tokens.Filter", g08 + "/store/tokens.Shapes.FetchStamp"})
}
