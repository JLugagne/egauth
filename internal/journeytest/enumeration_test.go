package journeytest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	timingSamples  = 200
	timingFloor    = 2 * time.Millisecond
	timingFraction = 10
	quiet          = 120 * time.Millisecond
)

func enumerationShapes() []shape {
	return []shape{{backend: journeytest.JWT}, {backend: journeytest.JWT, bearer: true}}
}

type fastSeeder struct {
	w   *journeytest.World
	phc identity.PasswordHash
}

func newFastSeeder(t testing.TB, w *journeytest.World) *fastSeeder {
	t.Helper()
	phc, err := argon2.NewHasher().Hash(context.Background(), journeytest.Password)
	require.NoError(t, err)
	return &fastSeeder{w: w, phc: identity.NewPasswordHash(phc)}
}

func (f *fastSeeder) user(t testing.TB, email string) {
	t.Helper()
	id, err := identity.NewIdentifier(identity.IdentifierEmail, email)
	require.NoError(t, err)
	_, err = f.w.Storage.Identity.Apply(context.Background(), identity.CreateVerified{Tenant: f.w.Tenant, Email: id, PHC: f.phc})
	require.NoError(t, err)
}

type outcome struct {
	status    int
	body      string
	bodyLen   int
	cookies   []string
	headers   []string
	delivered int
	elsewhere int
}

var randomMembers = map[string]bool{"handle": true, "bind": true, "flow": true, "challenge": true, "id": true, "token": true, "authorization_url": true}

func maskRandom(v any, extra map[string]bool) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = maskRandom(x[i], extra)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			switch {
			case extra[k]:
				out[k] = "<masked>"
			case randomMembers[k]:
				if str, ok := e.(string); ok {
					out[k] = fmt.Sprintf("<%d chars>", len(str))
				} else {
					out[k] = maskRandom(e, extra)
				}
			default:
				out[k] = maskRandom(e, extra)
			}
		}
		return out
	}
	return v
}

func observe(t testing.TB, r *journeytest.Resp, extra ...string) outcome {
	t.Helper()
	masked := map[string]bool{}
	for _, k := range extra {
		masked[k] = true
	}
	o := outcome{status: r.Status, bodyLen: len(r.Body)}
	if len(extra) > 0 {
		o.bodyLen = -1
	}
	var v any
	if len(r.Body) > 0 && json.Unmarshal(r.Body, &v) == nil {
		b, err := json.Marshal(maskRandom(v, masked))
		require.NoError(t, err)
		o.body = string(b)
	} else {
		o.body = string(r.Body)
	}
	for _, k := range r.Cookies {
		o.cookies = append(o.cookies, fmt.Sprintf("%s|%d|%s|%t|%t|%v|%d", k.Name, k.MaxAge, k.Path, k.HttpOnly, k.Secure, k.SameSite, len(k.Value)))
	}
	sort.Strings(o.cookies)
	for name, vs := range r.Header {
		switch name {
		case "Date", "Set-Cookie":
			continue
		case "Content-Length":
			if len(extra) > 0 {
				continue
			}
		}
		if strings.HasPrefix(name, "X-Egauth-") {
			o.headers = append(o.headers, name+"|"+fmt.Sprint(len(strings.Join(vs, ","))))
			continue
		}
		o.headers = append(o.headers, name+"|"+strings.Join(vs, ","))
	}
	sort.Strings(o.headers)
	return o
}

func requireUniform(t testing.TB, what string, existing, unknown outcome) {
	t.Helper()
	require.Equal(t, existing.status, unknown.status, what+": status differs")
	require.Equal(t, existing.body, unknown.body, what+": body differs")
	require.Equal(t, existing.bodyLen, unknown.bodyLen, what+": body length differs")
	require.Equal(t, existing.cookies, unknown.cookies, what+": cookies differ")
	require.Equal(t, existing.headers, unknown.headers, what+": headers differ")
	require.Equal(t, existing.elsewhere, unknown.elsewhere, what+": deliveries to other addresses differ")
	require.Zero(t, existing.elsewhere, what+": a message went to an address other than the identifier")
}

func deliveriesAfter(w *journeytest.World, mailMark, textMark int, identifier string) (toIdentifier, elsewhere int) {
	time.Sleep(quiet)
	for _, m := range w.Mailbox.Messages()[mailMark:] {
		if m.To == identifier {
			toIdentifier++
		} else {
			elsewhere++
		}
	}
	elsewhere += len(w.SMS.Messages()[textMark:])
	return toIdentifier, elsewhere
}

type enumProbe struct {
	name     string
	path     string
	fields   func(identifier string) map[string]any
	existing func(t testing.TB, w *journeytest.World, f *fastSeeder) string
	toTarget [2]int
}

func newEmail(t testing.TB, w *journeytest.World, f *fastSeeder) string {
	email := w.FreshEmail("exists")
	f.user(t, email)
	return email
}

func identifierOnly(identifier string) map[string]any {
	return map[string]any{egauth.FieldIdentifier: identifier}
}

func enumProbes() []enumProbe {
	return []enumProbe{
		{name: "register", path: egauth.PathRegister, existing: newEmail, toTarget: [2]int{1, 1},
			fields: func(id string) map[string]any {
				return map[string]any{egauth.FieldIdentifier: id, egauth.FieldPassword: strongPassword}
			}},
		{name: "password-forgot", path: egauth.PathPasswordForgot, existing: newEmail, toTarget: [2]int{1, 0}, fields: identifierOnly},
		{name: "magic-link-request", path: egauth.PathMagicLinkRequest, existing: newEmail, toTarget: [2]int{1, 0}, fields: identifierOnly},
		{name: "email-verify-request", path: egauth.PathEmailVerifyRequest, existing: newEmail, toTarget: [2]int{0, 0}, fields: identifierOnly},
		{name: "code-request-email", path: egauth.PathCodeRequest, existing: newEmail, toTarget: [2]int{1, 0}, fields: identifierOnly},
	}
}

func TestEnumerationExistingAndUnknownIdentifiersAreIndistinguishable(t *testing.T) {
	for _, s := range enumerationShapes() {
		for _, p := range enumProbes() {
			t.Run(s.String()+"/"+p.name, func(t *testing.T) {
				w := journeytest.NewWorld(t, s.settings())
				f := newFastSeeder(t, w)
				run := func(identifier string) outcome {
					mailMark, textMark := len(w.Mailbox.Messages()), len(w.SMS.Messages())
					c := w.NewClient()
					res := c.Post(p.path, p.fields(identifier))
					o := observe(t, res)
					o.delivered, o.elsewhere = deliveriesAfter(w, mailMark, textMark, identifier)
					return o
				}
				existing := run(p.existing(t, w, f))
				unknown := run(w.FreshEmail("ghost"))
				requireUniform(t, p.name, existing, unknown)
				require.Equal(t, p.toTarget[0], existing.delivered, p.name+": messages to an existing identifier")
				require.Equal(t, p.toTarget[1], unknown.delivered, p.name+": messages to an unknown identifier")
				require.Less(t, existing.status, http.StatusBadRequest)
			})
		}
	}
}

func TestEnumerationTextCodeRequestsAreIndistinguishable(t *testing.T) {
	for _, s := range enumerationShapes() {
		t.Run(s.String(), func(t *testing.T) {
			w := journeytest.NewWorld(t, s.settings())
			phone := "+14155550133"
			verifyPhone(t, w, newAccount(t, w, s, "phoneowner"), phone)

			run := func(identifier string) outcome {
				mailMark, textMark := len(w.Mailbox.Messages()), len(w.SMS.Messages())
				res := w.NewClient().Post(egauth.PathCodeRequest, identifierOnly(identifier))
				o := observe(t, res)
				time.Sleep(quiet)
				o.delivered = len(w.SMS.Messages()) - textMark
				o.elsewhere = len(w.Mailbox.Messages()) - mailMark
				return o
			}
			existing := run(phone)
			unknown := run("+14155550199")
			requireUniform(t, "code-request-sms", existing, unknown)
			require.Equal(t, 1, existing.delivered)
			require.Equal(t, 0, unknown.delivered)
		})
	}
}

func verifyPhone(t testing.TB, w *journeytest.World, a *account, phone string) {
	t.Helper()
	sess := a.signIn(false)
	n := w.TextCount("PhoneVerificationCode")
	begin := sess.post(egauth.PathPhoneVerifyRequest, map[string]any{egauth.FieldPhone: phone})
	require.Equal(t, http.StatusOK, begin.Status, journeytest.Describe(begin))
	code := w.WaitText("PhoneVerificationCode", n+1).Code
	verified := sess.post(egauth.PathPhoneVerify, map[string]any{egauth.FieldHandle: begin.Field(egauth.FieldHandle), egauth.FieldCode: code})
	require.Equal(t, http.StatusOK, verified.Status, journeytest.Describe(verified))
	settle(w)
}

func TestEnumerationPhoneLoginAndPasskeyOptionsAreIndistinguishable(t *testing.T) {
	for _, s := range enumerationShapes() {
		t.Run(s.String(), func(t *testing.T) {
			w := journeytest.NewWorld(t, s.settings())
			owner := newAccount(t, w, s, "phonelogin")
			phone := "+14155550144"
			verifyPhone(t, w, owner, phone)
			owner.withPasskeys(1)

			login := func(phone string) outcome {
				res := w.NewClient().Post(egauth.PathLogin, map[string]any{egauth.FieldIdentifier: phone, egauth.FieldPassword: "not the password"})
				return observe(t, res)
			}
			unknown := login("+14155550188")
			require.Equal(t, http.StatusUnauthorized, unknown.status)
			requireUniform(t, "phone login with a wrong password", login(phone), unknown)

			begin := func(phone string) outcome {
				res := w.NewClient().Post(egauth.PathPasskeyLoginBegin, map[string]any{egauth.FieldIdentifier: phone})
				return observe(t, res, "allowCredentials")
			}
			requireUniform(t, "phone passkey login begin", begin(phone), begin("+14155550177"))
		})
	}
}

func TestEnumerationPasswordLoginFailuresAreIndistinguishable(t *testing.T) {
	for _, s := range enumerationShapes() {
		t.Run(s.String(), func(t *testing.T) {
			w := journeytest.NewWorld(t, s.settings())
			wrongPassword := newAccount(t, w, s, "wrongpw")
			disabled := newAccount(t, w, s, "disabled")
			w.SetDisabled(disabled.Sub, true)
			deleted := newAccount(t, w, s, "deleted")
			sess := deleted.signIn(false)
			require.Equal(t, http.StatusOK, sess.post(egauth.PathAccountDelete, map[string]any{}).Status)
			waitFor(t, "the deleted account to be gone", func() bool {
				_, err := w.Storage.Identity.GetUser(context.Background(), deleted.Sub)
				return err != nil
			})
			settle(w)

			attempt := func(email, password string) outcome {
				return observe(t, w.NewClient().LoginPassword(journeytest.Credentials{Email: email, Password: password}, s.bearer))
			}
			unknown := attempt(w.FreshEmail("ghost"), journeytest.Password)
			require.Equal(t, http.StatusUnauthorized, unknown.status)
			require.Contains(t, unknown.body, "invalid_credentials")
			for name, got := range map[string]outcome{
				"wrong password":         attempt(wrongPassword.Email, "not the password"),
				"disabled, right secret": attempt(disabled.Email, journeytest.Password),
				"deleted, right secret":  attempt(deleted.Email, journeytest.Password),
			} {
				requireUniform(t, "login "+name, got, unknown)
			}
		})
	}
}

func TestEnumerationUsernameFirstPasskeyOptionsAreIndistinguishable(t *testing.T) {
	for _, s := range enumerationShapes() {
		t.Run(s.String(), func(t *testing.T) {
			w := journeytest.NewWorld(t, s.settings())
			a := newAccount(t, w, s, "haskey")
			a.withPasskeys(1)
			plain := newAccount(t, w, s, "nokey")
			disabled := newAccount(t, w, s, "offkey")
			w.SetDisabled(disabled.Sub, true)

			begin := func(identifier string) (*journeytest.Resp, outcome) {
				res := w.NewClient().Post(egauth.PathPasskeyLoginBegin, map[string]any{egauth.FieldIdentifier: identifier})
				return res, observe(t, res, "allowCredentials")
			}
			realRes, real := begin(a.Email)
			ghost := w.FreshEmail("ghost")
			ghostRes, fake := begin(ghost)
			require.Equal(t, http.StatusOK, realRes.Status, journeytest.Describe(realRes))
			requireUniform(t, "passkey login begin", real, fake)
			for name, email := range map[string]string{"no passkey": plain.Email, "disabled": disabled.Email} {
				_, o := begin(email)
				requireUniform(t, "passkey login begin of an account with "+name, o, fake)
			}

			ids := func(r *journeytest.Resp) []string {
				var b struct {
					Options struct {
						PublicKey struct {
							Allow []struct {
								ID string `json:"id"`
							} `json:"allowCredentials"`
						} `json:"publicKey"`
					} `json:"options"`
				}
				require.NoError(t, json.Unmarshal(r.Body, &b))
				var out []string
				for _, c := range b.Options.PublicKey.Allow {
					out = append(out, c.ID)
				}
				return out
			}
			require.NotEmpty(t, ids(ghostRes), "an unknown identifier must get fake credential ids")
			_, _ = begin(ghost)
			again, _ := begin(ghost)
			require.Equal(t, ids(ghostRes), ids(again), "the fake credential ids of one identifier must be stable")
			other, _ := begin(w.FreshEmail("ghost2"))
			require.NotEqual(t, ids(ghostRes), ids(other), "two unknown identifiers shared fake credential ids")
			for _, id := range ids(ghostRes) {
				require.False(t, slices.Contains(ids(realRes), id))
			}
		})
	}
}

func median(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[len(s)/2]
}

func medianGap(existing, unknown time.Duration) (diff, tolerance time.Duration) {
	diff = existing - unknown
	if diff < 0 {
		diff = -diff
	}
	tolerance = max(existing, unknown) / timingFraction
	return diff, max(tolerance, timingFloor)
}

func TestEnumerationTimingToleranceScalesWithTheEndpoint(t *testing.T) {
	cases := []struct {
		name              string
		existing, unknown time.Duration
		detected          bool
	}{
		{"fast endpoint with a 10ms existence delay", 10530 * time.Microsecond, 306 * time.Microsecond, true},
		{"fast endpoint with a 3ms existence delay", 3100 * time.Microsecond, 100 * time.Microsecond, true},
		{"fast endpoint with ordinary noise", 109 * time.Microsecond, 105 * time.Microsecond, false},
		{"hash endpoint with a removed decoy hash", 24 * time.Millisecond, 400 * time.Microsecond, true},
		{"hash endpoint with ordinary noise", 24490 * time.Microsecond, 24030 * time.Microsecond, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			diff, tolerance := medianGap(c.existing, c.unknown)
			require.Equal(t, c.detected, diff >= tolerance, "diff %v tolerance %v", diff, tolerance)
		})
	}
}

type timedPair struct {
	name    string
	prepare func(t testing.TB, w *journeytest.World, f *fastSeeder, n int) (existing, unknown func(i int) *journeytest.Resp)
}

func fresh(c *journeytest.Client, path string, fields map[string]any) *journeytest.Resp {
	return c.Do(journeytest.Req{Method: http.MethodPost, Path: "/auth" + path, JSON: fields, Remote: c.FreshRemote()})
}

func timedPairs() []timedPair {
	endpoint := func(name, path string, fields func(string) map[string]any) timedPair {
		return timedPair{name: name, prepare: func(t testing.TB, w *journeytest.World, f *fastSeeder, n int) (func(int) *journeytest.Resp, func(int) *journeytest.Resp) {
			emails := make([]string, n)
			for i := range emails {
				emails[i] = w.FreshEmail("timed")
				f.user(t, emails[i])
			}
			c := w.NewClient()
			return func(i int) *journeytest.Resp { return fresh(c, path, fields(emails[i])) },
				func(i int) *journeytest.Resp { return fresh(c, path, fields(w.FreshEmail("ghost"))) }
		}}
	}
	return []timedPair{
		endpoint("register", egauth.PathRegister, func(id string) map[string]any {
			return map[string]any{egauth.FieldIdentifier: id, egauth.FieldPassword: strongPassword}
		}),
		endpoint("password-forgot", egauth.PathPasswordForgot, identifierOnly),
		endpoint("magic-link-request", egauth.PathMagicLinkRequest, identifierOnly),
		endpoint("email-verify-request", egauth.PathEmailVerifyRequest, identifierOnly),
		endpoint("code-request", egauth.PathCodeRequest, identifierOnly),
		{name: "login", prepare: func(t testing.TB, w *journeytest.World, f *fastSeeder, n int) (func(int) *journeytest.Resp, func(int) *journeytest.Resp) {
			emails := make([]string, n)
			for i := range emails {
				emails[i] = w.FreshEmail("timed")
				f.user(t, emails[i])
			}
			c := w.NewClient()
			attempt := func(email string) *journeytest.Resp {
				return fresh(c, egauth.PathLogin, map[string]any{egauth.FieldIdentifier: email, egauth.FieldPassword: "not the password"})
			}
			return func(i int) *journeytest.Resp { return attempt(emails[i]) },
				func(i int) *journeytest.Resp { return attempt(w.FreshEmail("ghost")) }
		}},
		{name: "passkey-login-begin", prepare: func(t testing.TB, w *journeytest.World, _ *fastSeeder, n int) (func(int) *journeytest.Resp, func(int) *journeytest.Resp) {
			const perIdentifier = 5
			s := shape{backend: journeytest.JWT}
			holders := make([]string, (n+perIdentifier-1)/perIdentifier)
			ghosts := make([]string, len(holders))
			for i := range holders {
				a := newAccount(t, w, s, "timedkey")
				a.withPasskeys(1)
				holders[i], ghosts[i] = a.Email, w.FreshEmail("ghost")
			}
			c := w.NewClient()
			begin := func(email string) *journeytest.Resp {
				return fresh(c, egauth.PathPasskeyLoginBegin, identifierOnly(email))
			}
			return func(i int) *journeytest.Resp { return begin(holders[i/perIdentifier]) },
				func(i int) *journeytest.Resp { return begin(ghosts[i/perIdentifier]) }
		}},
	}
}

func TestEnumerationTimingMediansAreWithinTolerance(t *testing.T) {
	if testing.Short() {
		t.Skip("timing medians over 200 samples are not part of make check")
	}
	s := shape{backend: journeytest.JWT}
	for _, p := range timedPairs() {
		t.Run(p.name, func(t *testing.T) {
			w := journeytest.NewWorld(t, s.settings())
			f := newFastSeeder(t, w)
			existing, unknown := p.prepare(t, w, f, timingSamples)
			var known, ghost []time.Duration
			for i := range timingSamples {
				start := time.Now()
				a := existing(i)
				known = append(known, time.Since(start))
				start = time.Now()
				b := unknown(i)
				ghost = append(ghost, time.Since(start))
				require.Equal(t, a.Status, b.Status, "sample %d: %s vs %s", i, journeytest.Describe(a), journeytest.Describe(b))
				require.NotEqual(t, http.StatusTooManyRequests, a.Status, "sample %d was rate limited", i)
			}
			diff, tolerance := medianGap(median(known), median(ghost))
			t.Logf("%s: existing median %v, unknown median %v", p.name, median(known), median(ghost))
			require.Less(t, diff, tolerance, "%s: the medians of %d samples differ by %v, over the %v tolerance (existing %v, unknown %v)", p.name, timingSamples, diff, tolerance, median(known), median(ghost))
		})
	}
}
