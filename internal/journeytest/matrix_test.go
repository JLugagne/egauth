package journeytest_test

import (
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/journeytest"
)

const goldenPath = "testdata/short-matrix.golden"

func TestMatrixEveryModuleHasADriver(t *testing.T) {
	drivers := journeytest.Drivers()
	fields := journeytest.ModulesFields()
	want := reflect.TypeFor[egauth.Modules]().NumField()
	require.Len(t, fields, want)
	for _, name := range fields {
		d, ok := drivers[name]
		require.True(t, ok, "Modules.%s has no journey driver", name)
		require.Equal(t, name, d.Module)
		owns := len(d.Primaries)+len(d.Seconds) > 0
		require.True(t, owns || d.Check != nil, "driver of Modules.%s owns no dimension value and runs no check", name)
	}
	for name := range drivers {
		require.True(t, slices.Contains(fields, name), "driver %q is not a field of egauth.Modules", name)
	}
}

func TestMatrixDriversOwnEveryDimensionValueOnce(t *testing.T) {
	owners := map[journeytest.Primary]int{}
	seconds := map[journeytest.MFA]int{}
	for module, d := range journeytest.Drivers() {
		for _, p := range d.Primaries {
			owners[p.Primary]++
			require.Equal(t, module, p.Module)
			require.NotEmpty(t, p.Factors)
			require.NotNil(t, p.Prepare)
			require.NotNil(t, p.Login)
		}
		for _, s := range d.Seconds {
			seconds[s.MFA]++
			require.Equal(t, module, s.Module)
			require.NotEmpty(t, s.Factor)
			require.NotNil(t, s.Enroll)
			require.NotNil(t, s.Complete)
		}
	}
	for _, p := range journeytest.Primaries() {
		require.Equal(t, 1, owners[p], "primary %s", p)
	}
	for _, m := range journeytest.MFAs() {
		want := 1
		if m == journeytest.MFANone {
			want = 0
		}
		require.Equal(t, want, seconds[m], "mfa %s", m)
	}
}

func TestMatrixDriverModulesAreEnabledInTheGoldenConfiguration(t *testing.T) {
	w := journeytest.NewWorld(t, journeytest.Settings{})
	for module := range journeytest.Drivers() {
		require.True(t, journeytest.ModuleEnabled(w.Config, module), "Modules.%s is off in the golden configuration", module)
	}
}

func TestMatrixExemptionsAreTypedAndResolvable(t *testing.T) {
	list := journeytest.CellExemptions()
	require.Len(t, list, journeytest.MaxCellExemptions, "adding or removing an exemption must raise or lower MaxCellExemptions in the same diff")
	seen := map[[2]string]bool{}
	for _, e := range list {
		require.True(t, journeytest.ResolveSymbol(e.Symbol), "exemption symbol %s no longer resolves", e.Symbol)
		require.NotEmpty(t, e.ReliesOnAbsenceOf)
		require.False(t, journeytest.ResolveSymbol(e.ReliesOnAbsenceOf), "%s exists now: the exemption of %s+%s is stale", e.ReliesOnAbsenceOf, e.Primary, e.MFA)
		require.Contains(t, journeytest.Primaries(), e.Primary)
		require.Contains(t, journeytest.MFAs(), e.MFA)
		require.NotEqual(t, journeytest.MFANone, e.MFA)
		key := [2]string{string(e.Primary), string(e.MFA)}
		require.False(t, seen[key], "duplicate exemption %v", key)
		seen[key] = true
	}
}

func TestMatrixEveryExemptionWaivesCells(t *testing.T) {
	all := journeytest.AllCells()
	full := journeytest.FullMatrix()
	waived := len(all) - len(full)
	per := len(all) / (len(journeytest.Primaries()) * len(journeytest.MFAs()))
	require.Equal(t, journeytest.MaxCellExemptions*per, waived)
	for _, c := range full {
		_, skipped := journeytest.Exempted(c)
		require.False(t, skipped, c.String())
	}
}

func TestMatrixResolveSymbolRefusesUnknownPaths(t *testing.T) {
	for _, bad := range []string{"", ".", "Config.", "Config..Modules", "Config.Modules.", "Auth", "Auth.", "Config.Modules.Nope", "Config.Nope.Password", "Auth.Nope", "Auth.Routes.Nope", "Other.Modules", "Config.Modules.Password.Registration.Deeper"} {
		require.False(t, journeytest.ResolveSymbol(bad), bad)
	}
	for _, good := range []string{"Config.Modules.Password.Registration", "Config.Modules.MFA", "Config", "Auth.Routes", "Auth.Close", "Auth.Routes.Build"} {
		require.True(t, journeytest.ResolveSymbol(good), good)
	}
}

func TestMatrixCellRoundTrips(t *testing.T) {
	for _, c := range journeytest.AllCells() {
		got, err := journeytest.ParseCell(c.String())
		require.NoError(t, err)
		require.Equal(t, c, got)
	}
	for _, bad := range []string{"", "password+none", "password/jwt/cookies/single", "nope+none/jwt/cookies/single", "password+none/x/cookies/single", "password+none/jwt/x/single", "password+none/jwt/cookies/x"} {
		_, err := journeytest.ParseCell(bad)
		require.Error(t, err, bad)
	}
}

func TestMatrixFullSizeIsTheCrossProductMinusExemptions(t *testing.T) {
	require.Equal(t, 10*4*2*2*2, len(journeytest.AllCells()))
	require.Equal(t, len(journeytest.AllCells())-3*8, len(journeytest.FullMatrix()))
}

type pairKey struct {
	a, b string
}

func dimensionValues(c journeytest.Cell) [5]string {
	return [5]string{string(c.Primary), string(c.MFA), c.Backend.String(), c.Carrier.String(), strconv.Itoa(int(c.Tenancy))}
}

func pairsOf(cells []journeytest.Cell) map[[2]int]map[pairKey]bool {
	out := map[[2]int]map[pairKey]bool{}
	for _, c := range cells {
		v := dimensionValues(c)
		for i := range v {
			for j := i + 1; j < len(v); j++ {
				k := [2]int{i, j}
				if out[k] == nil {
					out[k] = map[pairKey]bool{}
				}
				out[k][pairKey{v[i], v[j]}] = true
			}
		}
	}
	return out
}

func TestMatrixPairwiseCoversEveryReachablePair(t *testing.T) {
	want := pairsOf(journeytest.FullMatrix())
	got := pairsOf(journeytest.Pairwise(journeytest.PairwiseSeed))
	for k, pairs := range want {
		for p := range pairs {
			require.True(t, got[k][p], "dimensions %v: pair %v is not covered", k, p)
		}
	}
	for _, c := range journeytest.Pairwise(journeytest.PairwiseSeed) {
		_, skipped := journeytest.Exempted(c)
		require.False(t, skipped, "the covering array holds the waived cell %s", c)
	}
}

func TestMatrixPairwiseIsDeterministicPerSeed(t *testing.T) {
	a := journeytest.Pairwise(journeytest.PairwiseSeed)
	require.Equal(t, a, journeytest.Pairwise(journeytest.PairwiseSeed))
	require.NotEmpty(t, a)
}

func TestMatrixShortIsTheUnionOfPrimaryByMFAAndPairwise(t *testing.T) {
	short := journeytest.ShortMatrix()
	in := map[journeytest.Cell]bool{}
	for _, c := range short {
		require.False(t, in[c], "duplicate %s", c)
		in[c] = true
	}
	for _, c := range journeytest.PrimaryByMFA() {
		require.True(t, in[c], "%s is missing", c)
		require.Equal(t, journeytest.JWT, c.Backend)
		require.Equal(t, journeytest.Cookies, c.Carrier)
		require.Equal(t, journeytest.Single, c.Tenancy)
	}
	for _, c := range journeytest.Pairwise(journeytest.PairwiseSeed) {
		require.True(t, in[c], "%s is missing", c)
	}
	require.Len(t, journeytest.PrimaryByMFA(), 10*4-3)
	require.Less(t, len(short), len(journeytest.FullMatrix()))
}

func TestShortMatrixGolden(t *testing.T) {
	got := journeytest.Golden(journeytest.ShortMatrix())
	if os.Getenv("JOURNEYTEST_UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o750))
		require.NoError(t, os.WriteFile(goldenPath, []byte(got), 0o600))
	}
	want, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "regenerate with JOURNEYTEST_UPDATE_GOLDEN=1")
	require.Equal(t, string(want), got, "the short matrix changed: regenerate %s with JOURNEYTEST_UPDATE_GOLDEN=1 and review the diff", goldenPath)
}

func TestMatrixGoldenCellsAreTheShortMatrix(t *testing.T) {
	raw, err := os.ReadFile(goldenPath)
	require.NoError(t, err)
	var cells []journeytest.Cell
	for _, line := range splitLines(string(raw)) {
		c, err := journeytest.ParseCell(line)
		require.NoError(t, err)
		cells = append(cells, c)
	}
	require.Equal(t, journeytest.ShortMatrix(), cells)
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := range s {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

func TestMatrixJourneys(t *testing.T) {
	cells := journeytest.FullMatrix()
	if testing.Short() {
		cells = journeytest.ShortMatrix()
	}
	journeytest.RunMatrix(t, cells)
}

func TestMatrixSupportModulesRunARealCheck(t *testing.T) {
	drivers := journeytest.Drivers()
	for name, d := range drivers {
		require.True(t, len(d.Primaries)+len(d.Seconds) > 0 || d.Check != nil, "Modules.%s is driven by a sentence, not by a check", name)
	}
	require.True(t, drivers["SelfDelete"].Terminal, "account deletion ends the session, so it must run after every other check")
}

func TestMatrixEstablishCellHandsBackALiveSession(t *testing.T) {
	cell := journeytest.Cell{Primary: journeytest.PrimaryPassword, MFA: journeytest.MFATOTP, Backend: journeytest.JWT, Carrier: journeytest.Cookies, Tenancy: journeytest.Single}
	r, c := journeytest.EstablishCell(t, cell)
	require.NotNil(t, r)
	require.NotNil(t, c)
	require.Equal(t, cell, r.Cell)
	require.NotEmpty(t, r.Want.Subject)
	require.Equal(t, http.StatusOK, c.Session().Status)
	_, done := journeytest.RunCell(t, cell)
	require.Equal(t, http.StatusUnauthorized, done.Session().Status, "RunCell ends with the terminal checks: the account is deleted")
}

func TestMatrixSelfSufficientCellsEnrollDistinctSecondFactors(t *testing.T) {
	cell := func(m journeytest.MFA) journeytest.Cell {
		return journeytest.Cell{Primary: journeytest.PrimaryPasskeyDiscoverable, MFA: m, Backend: journeytest.JWT, Carrier: journeytest.Cookies, Tenancy: journeytest.Single}
	}
	totp, _ := journeytest.RunCell(t, cell(journeytest.MFATOTP))
	require.NotEmpty(t, totp.Secret)
	require.Nil(t, totp.StepUp)

	recovery, _ := journeytest.RunCell(t, cell(journeytest.MFARecoveryCode))
	require.NotEmpty(t, recovery.Recovery)
	require.Greater(t, len(recovery.World.Events.Of(event.CredentialAdded)), len(totp.World.Events.Of(event.CredentialAdded)),
		"the recovery cell must regenerate the recovery codes on top of enrolling TOTP")

	stepUp, _ := journeytest.RunCell(t, cell(journeytest.MFAPasskeyStepUp))
	require.NotNil(t, stepUp.StepUp)
	require.NotSame(t, stepUp.Passkey, stepUp.StepUp)
	require.Empty(t, stepUp.Secret)
}

func TestMatrixEstablishCellRememberingHonoursTheChoice(t *testing.T) {
	for _, backend := range []journeytest.Backend{journeytest.JWT, journeytest.Stateful} {
		for _, remember := range []bool{true, false} {
			cell := journeytest.Cell{Primary: journeytest.PrimaryPassword, MFA: journeytest.MFANone, Backend: backend, Carrier: journeytest.Cookies, Tenancy: journeytest.Single}
			r, _ := journeytest.EstablishCellRemembering(t, cell, remember)
			require.Equal(t, remember, r.Remember)
			require.Equal(t, remember, r.Want.RememberMe)
		}
	}
}
