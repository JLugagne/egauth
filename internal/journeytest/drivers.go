package journeytest

import (
	"encoding/json"
	"hash/fnv"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/webauthntest"
)

// Fixed request values of every journey: the matrix asserts that remember-me and the return target
// sealed at the primary step survive to the session.
const (
	JourneyReturnTo   = "/app"
	journeyPhone      = "+15555550123"
	verificationPhone = "+15555550188"
	mfaPage           = "/mfa"
	registerPassword  = "journey-matrix lemon harbor 7Q!"
)

// Run is the state of one matrix cell while its drivers act: the World, the account the primary
// factor signs in, and the second-factor material the enrollment produced.
type Run struct {
	T        testing.TB
	World    *World
	Cell     Cell
	Email    string
	Phone    string
	Account  principal.Subject
	Secret   string
	Recovery []string
	Passkey  *webauthntest.Authenticator
	StepUp   *webauthntest.Authenticator
	// Remember is the remember-me choice of the cell's journey; it varies across cells so that both values are asserted.
	Remember bool
	// Want is the session EstablishCell asserted at the end of the journey, for the checks and scenarios that continue from it.
	Want Expected
}

func rememberFor(c Cell) bool {
	h := fnv.New32a()
	_, _ = h.Write([]byte(c.String()))
	return h.Sum32()&1 == 0
}

// PrimaryDriver realizes one Primary through the public endpoints of the Auth under test.
type PrimaryDriver struct {
	Primary Primary
	// Module is the egauth.Modules field that serves the primary.
	Module string
	// Factors are the factor codes the primary leaves on the session.
	Factors []string
	// SelfSufficient is true when Factors already make the session multi-factor, so that an
	// enrolled second factor is never asked for.
	SelfSufficient bool
	// JIT is true when the first sign-in creates the account.
	JIT bool
	// LegEvents are the event types the primary leg emits before the session is admitted or parked.
	LegEvents []event.Type
	// CreateEvents replaces LegEvents on the sign-in that creates the account of a JIT primary.
	CreateEvents []event.Type
	// Settings adjusts the World the cell runs on.
	Settings func(*Settings)
	// Prepare creates the account the primary signs in; it may sign it in and enroll credentials.
	Prepare func(*Run)
	// Login runs the primary leg on c and returns the response that admitted the session or parked the flow.
	Login func(*Run, *Client) *Resp
}

// SecondDriver realizes one MFA variant.
type SecondDriver struct {
	MFA MFA
	// Module is the egauth.Modules field that completes the second factor.
	Module string
	// Factor is the code of the factor a completed challenge adds to the session.
	Factor string
	// Verified is the event type a completed challenge emits, after the session issuance events
	// (DESIGN 5.1).
	Verified event.Type
	// Enroll enrolls the factor through the endpoints with the session of c. Each variant leaves a
	// distinct credential on the account, whether or not the journey later challenges it.
	Enroll func(*Run, *Client)
	// Complete answers the parked flow of c and returns the response that admitted the session.
	Complete func(*Run, *Client) *Resp
}

// ModuleDriver is what the matrix owns for one field of egauth.Modules.
type ModuleDriver struct {
	Module    string
	Primaries []PrimaryDriver
	Seconds   []SecondDriver
	// Support describes the matrix step the module serves when it owns no dimension value; it is documentation only.
	Support string
	// Check runs after every journey of a cell that enables the module. A module that owns no dimension value must have one.
	Check func(*Run, *Client)
	// Terminal is true when Check ends the session, so that it runs after every other Check.
	Terminal bool
}

// Drivers returns the driver of every field of egauth.Modules, keyed by field name. The set is
// checked against the struct by reflection, so that a new module without a driver fails the matrix.
func Drivers() map[string]ModuleDriver {
	out := map[string]ModuleDriver{}
	for _, p := range primaryDrivers() {
		d := out[p.Module]
		d.Module = p.Module
		d.Primaries = append(d.Primaries, p)
		out[p.Module] = d
	}
	for _, s := range secondDrivers() {
		d := out[s.Module]
		d.Module = s.Module
		d.Seconds = append(d.Seconds, s)
		out[s.Module] = d
	}
	for _, d := range supportDrivers() {
		cur := out[d.Module]
		cur.Module, cur.Support, cur.Check, cur.Terminal = d.Module, d.Support, d.Check, d.Terminal
		out[d.Module] = cur
	}
	return out
}

// ModulesFields returns the field names of egauth.Modules in declaration order.
func ModulesFields() []string {
	t := reflect.TypeFor[egauth.Modules]()
	out := make([]string, t.NumField())
	for i := range out {
		out[i] = t.Field(i).Name
	}
	return out
}

// ModuleEnabled reports whether the field of cfg.Modules named module is set.
func ModuleEnabled(cfg egauth.Config[Claims], module string) bool {
	f := reflect.ValueOf(cfg.Modules).FieldByName(module)
	return f.IsValid() && f.Kind() == reflect.Pointer && !f.IsNil()
}

func primaryDriverOf(p Primary) (PrimaryDriver, bool) {
	for _, d := range primaryDrivers() {
		if d.Primary == p {
			return d, true
		}
	}
	return PrimaryDriver{}, false
}

func secondDriverOf(m MFA) (SecondDriver, bool) {
	for _, d := range secondDrivers() {
		if d.MFA == m {
			return d, true
		}
	}
	return SecondDriver{}, false
}

func (r *Run) bearer() bool { return r.Cell.Carrier == Bearer }

func (r *Run) fields(extra map[string]any) map[string]any {
	f := map[string]any{egauth.FieldRemember: r.Remember, egauth.FieldReturnTo: JourneyReturnTo}
	maps.Copy(f, extra)
	return f
}

func (r *Run) post(c *Client, path string, fields map[string]any) *Resp {
	r.T.Helper()
	res := c.Do(Req{Method: http.MethodPost, Path: "/auth" + path, JSON: fields})
	c.keepTokens(res)
	return res
}

func (r *Run) withBind(c *Client, begin *Resp, fields map[string]any) map[string]any {
	if r.bearer() {
		fields[egauth.FieldBind] = c.Bind(begin)
	}
	return fields
}

func (r *Run) expect(res *Resp, status int, what string) {
	r.T.Helper()
	if res.Status != status {
		r.T.Fatalf("journeytest: %s: want %d, got %s", what, status, Describe(res))
	}
}

func (r *Run) established(res *Resp, what string) {
	r.T.Helper()
	if !res.Established() {
		r.T.Fatalf("journeytest: %s did not establish a session: %s", what, Describe(res))
	}
}

func isParked(res *Resp) bool {
	if res.Code() == "mfa_required" {
		return true
	}
	return res.Status == http.StatusSeeOther && res.Header.Get("Location") == mfaPage
}

func queryOf(link, key string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return u.Query().Get(key)
}

func mergeJSON(t testing.TB, raw []byte, extra map[string]any) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("journeytest: credential JSON: %v", err)
	}
	maps.Copy(m, extra)
	return m
}

type optionsBody struct {
	Options json.RawMessage `json:"options"`
	Handle  string          `json:"handle"`
}

func decodeOptions(t testing.TB, res *Resp) optionsBody {
	t.Helper()
	var b optionsBody
	if err := json.Unmarshal(res.Body, &b); err != nil || len(b.Options) == 0 {
		t.Fatalf("journeytest: no passkey options in %s", Describe(res))
	}
	return b
}

var amrOfFactor = map[string]string{
	"pwd": "pwd", "email_link": "email", "email_code": "otp", "sms_code": "sms", "fed": "fed", "ext": "ext",
	"pk": "hwk", "uv": "user", "totp": "otp", "rc": "rc", "pk_stepup": "hwk",
}

var secondFactorCodes = map[string]bool{"totp": true, "rc": true, "pk_stepup": true}

// Expected is the session a cell must end with, as GET /session and a Protect probe both report it.
type Expected struct {
	Subject                string
	Tenant                 string
	Factors                []string
	AMR                    []string
	RememberMe             bool
	ReturnTo               string
	PasswordChangeRequired bool
}

func expectedFactors(primary []string, second string) (factors, amr []string) {
	factors = append(factors, primary...)
	if second != "" {
		factors = append(factors, second)
	}
	sort.Strings(factors)
	hasPrimary, hasSecond := false, false
	for _, f := range factors {
		if secondFactorCodes[f] {
			hasSecond = true
		} else if f != "uv" {
			hasPrimary = true
		}
		if a := amrOfFactor[f]; a != "" && !slices.Contains(amr, a) {
			amr = append(amr, a)
		}
	}
	uv := slices.Contains(factors, "pk") && slices.Contains(factors, "uv")
	if (hasPrimary && hasSecond) || uv {
		amr = append(amr, "mfa")
	}
	return factors, amr
}

func (r *Run) settle() {
	r.World.Clock.Advance(revoke.PollBound + time.Second)
}

// String renders r without the TOTP secret, the recovery codes and the passkey, which are working credentials.
func (r Run) String() string {
	return "journeytest.Run{Cell: " + r.Cell.String() + ", Secrets: REDACTED}"
}

// GoString renders r for %#v without its credentials.
func (r Run) GoString() string { return r.String() }

// LogValue renders r for slog without its credentials.
func (r Run) LogValue() slog.Value {
	return slog.GroupValue(slog.String("cell", r.Cell.String()), slog.String("secrets", "REDACTED"))
}
