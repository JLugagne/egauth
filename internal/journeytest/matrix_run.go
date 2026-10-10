package journeytest

import (
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/principal"
)

// Settings returns the World settings that realize c, before any driver adjustment.
func (c Cell) Settings() Settings {
	s := Settings{Backend: c.Backend, Tenancy: c.Tenancy, Transport: egauth.Cookies}
	if c.Carrier == Bearer {
		s.Transport = egauth.Bearer
	}
	return s
}

// SessionView is the session as GET /session reports it and as a Protect handler sees it.
type SessionView struct {
	Subject                string   `json:"subject"`
	Tenant                 string   `json:"tenant"`
	Factors                []string `json:"factors"`
	AMR                    []string `json:"amr"`
	RememberMe             bool     `json:"remember_me"`
	ReturnTo               string   `json:"return_to"`
	PasswordChangeRequired bool     `json:"password_change_required"`
}

func viewOfAttrs(a principal.SessionAttrs) SessionView {
	fs := a.Factors()
	codes := make([]string, len(fs))
	for i, f := range fs {
		codes[i] = f.Code()
	}
	amr := a.AMR()
	if amr == nil {
		amr = []string{}
	}
	return SessionView{
		Subject: a.Subject().User.String(), Tenant: a.Subject().Tenant.String(), Factors: codes, AMR: amr,
		RememberMe: a.RememberMe(), ReturnTo: a.ReturnTo(), PasswordChangeRequired: a.MustChangePassword(),
	}
}

func (e Expected) view() SessionView { return SessionView(e) }

func equalViews(a, b SessionView) bool {
	return a.Subject == b.Subject && a.Tenant == b.Tenant && slices.Equal(a.Factors, b.Factors) && slices.Equal(a.AMR, b.AMR) &&
		a.RememberMe == b.RememberMe && a.ReturnTo == b.ReturnTo && a.PasswordChangeRequired == b.PasswordChangeRequired
}

// RunMatrix runs every cell as a subtest of t.
func RunMatrix(t *testing.T, cells []Cell) {
	t.Helper()
	for _, c := range cells {
		t.Run(c.String(), func(t *testing.T) { RunCell(t, c) })
	}
}

// RunCell is EstablishCell followed by the checks that end the session, such as account deletion; the
// Client it returns is therefore no longer signed in when the module of such a check is enabled.
func RunCell(t *testing.T, cell Cell) (*Run, *Client) {
	t.Helper()
	r, c := EstablishCell(t, cell)
	r.runChecks(c, true)
	return r, c
}

// EstablishCell runs the journey of one cell with the remember-me choice the matrix derives from the
// cell; see EstablishCellRemembering.
func EstablishCell(t *testing.T, cell Cell) (*Run, *Client) {
	t.Helper()
	return EstablishCellRemembering(t, cell, rememberFor(cell))
}

// EstablishCellRemembering runs the journey of one cell with the given remember-me choice: it builds
// the World, prepares the account, runs the primary leg and, with a second factor enrolled, the
// challenge; then it asserts the MFA ordering, the session as GET /session and a Protect probe report
// it, the carrier and backend the credential travels on, and the exact event sequence. A JIT primary
// without a second factor is measured on the sign-in that creates the account. It returns the Run and
// the Client holding the established session, so that a scenario can continue from it; the checks
// that end the session have not run. A cell that a typed exemption waives is skipped; any other cell
// the drivers cannot realize fails.
func EstablishCellRemembering(t *testing.T, cell Cell, remember bool) (*Run, *Client) {
	t.Helper()
	if e, skipped := Exempted(cell); skipped {
		t.Skipf("exempt by G20 (%s)", e.Symbol)
	}
	d, ok := primaryDriverOf(cell.Primary)
	if !ok {
		t.Fatalf("journeytest: no driver for primary %s", cell.Primary)
	}
	var sd SecondDriver
	if cell.MFA != MFANone {
		if sd, ok = secondDriverOf(cell.MFA); !ok {
			t.Fatalf("journeytest: no driver for MFA %s", cell.MFA)
		}
	}
	s := cell.Settings()
	if d.Settings != nil {
		d.Settings(&s)
	}
	w := NewWorld(t, s)
	for _, module := range []string{d.Module, sd.Module} {
		if module != "" && !ModuleEnabled(w.Config, module) {
			t.Fatalf("journeytest: Modules.%s is not enabled in the configuration under test", module)
		}
	}
	r := &Run{T: t, World: w, Cell: cell, Remember: remember}
	d.Prepare(r)

	parked := cell.MFA != MFANone && !d.SelfSufficient
	created := d.JIT && cell.MFA == MFANone
	if cell.MFA != MFANone {
		c := w.NewClient()
		r.established(d.Login(r, c), "warm-up sign-in")
		sd.Enroll(r, c)
	}
	if d.JIT && !created {
		lookupSubject(r)
	}

	mark := w.Events.Mark()
	c := w.NewClient()
	res := d.Login(r, c)
	if parked {
		r.assertParked(c, res)
		res = sd.Complete(r, c)
	} else if isParked(res) {
		t.Fatalf("journeytest: %s asked for a second factor although %v is multi-factor on its own: %s", cell.Primary, d.Factors, Describe(res))
	}
	r.established(res, "the journey")
	if created || d.Primary == PrimaryRegister {
		lookupSubject(r)
	}

	second := ""
	if parked {
		second = sd.Factor
	}
	factors, amr := expectedFactors(d.Factors, second)
	r.Want = Expected{
		Subject: r.Account.User.String(), Tenant: r.Account.Tenant.String(), Factors: factors, AMR: amr,
		RememberMe: r.Remember, ReturnTo: JourneyReturnTo,
	}
	r.assertSession(c, r.Want)
	r.assertCarrier(c)
	if got, wantEvents := w.Events.Since(mark), expectedEvents(d, sd, parked, created); !slices.Equal(got, wantEvents) {
		t.Fatalf("journeytest: event sequence\n got  %v\n want %v", got, wantEvents)
	}
	r.runChecks(c, false)
	return r, c
}

func (r *Run) runChecks(c *Client, terminal bool) {
	r.T.Helper()
	drivers := Drivers()
	names := make([]string, 0, len(drivers))
	for name := range drivers {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if md := drivers[name]; md.Check != nil && md.Terminal == terminal && ModuleEnabled(r.World.Config, name) {
			md.Check(r, c)
		}
	}
}

func expectedEvents(d PrimaryDriver, sd SecondDriver, parked, created bool) []event.Type {
	out := slices.Clone(d.LegEvents)
	if created {
		out = slices.Clone(d.CreateEvents)
	}
	issue := []event.Type{event.SessionIssued, event.LoginSucceeded}
	if !parked {
		return append(out, issue...)
	}
	out = append(out, event.MFAChallengeRequired)
	if sd.VerifiedAfterIssue {
		return append(append(out, issue...), sd.Verified)
	}
	return append(append(out, sd.Verified), issue...)
}

func (r *Run) assertParked(c *Client, res *Resp) {
	r.T.Helper()
	w := r.World
	if !isParked(res) {
		r.T.Fatalf("journeytest: the primary leg did not answer mfa_required first: %s", Describe(res))
	}
	if res.Established() || c.HasSessionCookie() || c.Bearer != "" {
		r.T.Fatalf("journeytest: a parked flow issued a session credential: %s", Describe(res))
	}
	handle := c.FlowHandle(res)
	if handle == "" {
		r.T.Fatalf("journeytest: the parked flow carries no handle: %s", Describe(res))
	}
	seen := w.Seen.Count()
	probe := c
	if r.bearer() {
		probe = w.NewClient()
		probe.Bearer = handle
	}
	if got := probe.Session(); got.Status != http.StatusUnauthorized {
		r.T.Fatalf("journeytest: GET /session with the MFA flow handle answered %d, want 401", got.Status)
	}
	if got := probe.Do(Req{Path: ProtectRoute}); got.Status != http.StatusUnauthorized || w.Seen.Count() != seen {
		r.T.Fatalf("journeytest: a Protect route accepted the MFA flow handle: %s", Describe(got))
	}
}

func (r *Run) assertSession(c *Client, want Expected) {
	r.T.Helper()
	w := r.World
	res := c.Session()
	r.expect(res, http.StatusOK, "GET /session")
	fromSession := decodeSession(r.T, res)
	seen := w.Seen.Count()
	probe := c.Do(Req{Path: ProtectRoute})
	r.expect(probe, http.StatusOK, "Protect probe")
	p, ok := w.Seen.Last()
	if w.Seen.Count() != seen+1 || !ok {
		r.T.Fatal("journeytest: the Protect probe did not reach its handler")
	}
	attrs, ok := p.Session()
	if !ok {
		r.T.Fatal("journeytest: the Protect probe saw no session")
	}
	fromProbe := viewOfAttrs(attrs)
	if !equalViews(fromSession, fromProbe) {
		r.T.Fatalf("journeytest: GET /session and the Protect probe disagree\n session %+v\n probe   %+v", fromSession, fromProbe)
	}
	if !equalViews(fromSession, want.view()) {
		r.T.Fatalf("journeytest: session differs from the expected value\n got  %+v\n want %+v", fromSession, want.view())
	}
}

var sessionMembers = func() []string {
	t := reflect.TypeFor[SessionView]()
	out := make([]string, t.NumField())
	for i := range out {
		out[i], _, _ = strings.Cut(t.Field(i).Tag.Get("json"), ",")
	}
	return out
}()

func decodeSession(t testing.TB, res *Resp) SessionView {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(res.Body, &members); err != nil {
		t.Fatalf("journeytest: GET /session body: %v", err)
	}
	for _, name := range sessionMembers {
		if _, ok := members[name]; !ok {
			t.Fatalf("journeytest: GET /session body has no %q member: %s", name, res.Body)
		}
	}
	var v SessionView
	if err := json.Unmarshal(res.Body, &v); err != nil {
		t.Fatalf("journeytest: GET /session body: %v", err)
	}
	if v.AMR == nil {
		v.AMR = []string{}
	}
	return v
}

func (r *Run) assertCarrier(c *Client) {
	r.T.Helper()
	w := r.World
	jwt := r.Cell.Backend == JWT
	if r.bearer() {
		if c.Bearer == "" || c.HasSessionCookie() {
			r.T.Fatalf("journeytest: a Bearer cell must hold a token and no session cookie (token %t, cookie %t)", c.Bearer != "", c.HasSessionCookie())
		}
		if isJWT := strings.Count(c.Bearer, ".") == 2; isJWT != jwt {
			r.T.Fatalf("journeytest: the Bearer token of a %s cell is a JWT: %t", r.Cell.Backend, isJWT)
		}
		jarOnly := w.Fork(c)
		jarOnly.Bearer = ""
		if got := jarOnly.Session(); got.Status != http.StatusUnauthorized {
			r.T.Fatalf("journeytest: a Bearer cell answered GET /session %d without its token, want 401", got.Status)
		}
		tokenOnly := w.NewClient()
		tokenOnly.Bearer = c.Bearer
		if got := tokenOnly.Session(); got.Status != http.StatusOK {
			r.T.Fatalf("journeytest: a Bearer cell answered GET /session %d with its token alone, want 200", got.Status)
		}
		return
	}
	if c.refresh != "" {
		r.T.Fatalf("journeytest: a cookies cell was handed a refresh token in a header")
	}
	for name, res := range map[string]*Resp{"GET /session": c.Session(), "Protect probe": c.Do(Req{Path: ProtectRoute})} {
		if res.Token() != "" || res.Refresh() != "" {
			r.T.Fatalf("journeytest: a cookies cell's %s response carries a token header: %s", name, Describe(res))
		}
	}
	_, hasAccess := c.Cookie("access_token")
	_, hasStateful := c.Cookie("-session")
	if c.Bearer != "" || hasAccess != jwt || hasStateful == jwt {
		r.T.Fatalf("journeytest: a cookies cell on the %s backend holds token %t, access cookie %t, stateful cookie %t", r.Cell.Backend, c.Bearer != "", hasAccess, hasStateful)
	}
}
