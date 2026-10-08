package configcheck_test

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/configcheck"
)

type store interface {
	Ping() error
}

type memStore struct{}

func (*memStore) Ping() error { return nil }

type deliverer interface {
	Send(to string) error
}

type mailer struct{}

func (mailer) Send(string) error { return nil }

type provider struct {
	Name   string
	Issuer string
}

type externalFactor struct {
	Name string
}

type passwordModule struct {
	Registration string `egauth:"default=registration_open"`
}

type loginCodeModule struct {
	Email bool
	SMS   bool
}

type passkeyModule struct {
	DisplayName string `egauth:"required,nonempty"`
}

type oauthModule struct {
	Providers []provider `egauth:"optional,each=provider"`
	PerTenant bool
}

type externalModule struct {
	Factors []externalFactor `egauth:"required,nonempty,each=external"`
}

type apiKeyModule struct {
	Kinds  []string `egauth:"required,nonempty,each=token"`
	Prefix string   `egauth:"default=api_key_prefix"`
}

type verificationModule struct {
	Email bool
	Phone bool
}

type modules struct {
	Password     *passwordModule
	LoginCode    *loginCodeModule
	Passkey      *passkeyModule
	OAuth        *oauthModule
	External     *externalModule
	APIKeys      *apiKeyModule
	Verification *verificationModule
}

type sessionPolicy struct {
	IdleTimeout  time.Duration `egauth:"default=idle_timeout,bound=le:MaxLifetime"`
	MaxLifetime  time.Duration `egauth:"default=max_lifetime,bound=max:2160h"`
	RecheckEvery time.Duration `egauth:"default=recheck_every,bound=max:15m"`
}

type storage struct {
	Identity   store `egauth:"required"`
	Tokens     store `egauth:"module=Sessions.JWT|APIKeys"`
	Federation store `egauth:"module=OAuth|External"`
}

type config struct {
	PublicOrigin string        `egauth:"required,origin"`
	BasePath     string        `egauth:"default=basepath,path"`
	ExtraOrigins []string      `egauth:"optional,each=origin"`
	Storage      storage       `egauth:"required"`
	Email        deliverer     `egauth:"module=Password|LoginCode.Email|Verification.Email"`
	Policy       sessionPolicy `egauth:"optional"`
	Modules      modules       `egauth:"required,oneof_primary"`
	Issuer       string        `egauth:"default=totp_issuer"`
}

var errBadProvider = errors.New("provider has no issuer")

func defaults() configcheck.Defaults {
	return configcheck.Defaults{
		"basepath":          func(*configcheck.Resolved) any { return "/auth" },
		"registration_open": func(*configcheck.Resolved) any { return "open" },
		"api_key_prefix":    func(*configcheck.Resolved) any { return "egk" },
		"idle_timeout":      func(*configcheck.Resolved) any { return 168 * time.Hour },
		"max_lifetime":      func(*configcheck.Resolved) any { return 720 * time.Hour },
		"recheck_every":     func(*configcheck.Resolved) any { return 5 * time.Minute },
		"totp_issuer": func(r *configcheck.Resolved) any {
			v, _ := r.Get("PublicOrigin")
			s, _ := v.(string)
			u, err := url.Parse(s)
			if err != nil || u.Hostname() == "" {
				return "egauth"
			}
			return u.Hostname()
		},
	}
}

func options() configcheck.Options {
	return configcheck.Options{
		Defaults: defaults(),
		Modules:  "Modules",
		Primary:  []string{"Password", "LoginCode.Email", "LoginCode.SMS", "Passkey", "OAuth", "External"},
		Switches: map[string]bool{"Sessions.JWT": false, "Sessions.Stateful": true},
		Provider: func(v any) error {
			p, _ := v.(provider)
			if p.Issuer == "" {
				return errBadProvider
			}
			return nil
		},
		External: func(v any) error {
			f, _ := v.(externalFactor)
			if strings.TrimSpace(f.Name) == "" {
				return errors.New("external factor has no name")
			}
			return nil
		},
	}
}

func validConfig() config {
	return config{
		PublicOrigin: "https://app.example.com",
		Storage:      storage{Identity: &memStore{}},
		Email:        mailer{},
		Modules:      modules{Password: &passwordModule{}},
	}
}

func validate(t *testing.T, c *config, o configcheck.Options) (*configcheck.Resolved, []*configcheck.Error) {
	t.Helper()
	return configcheck.Validate(c, o)
}

func problemFields(errs []*configcheck.Error) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Field)
	}
	return out
}

func requireOnly(t *testing.T, errs []*configcheck.Error, field string) *configcheck.Error {
	t.Helper()
	require.Len(t, errs, 1, "got %v", errs)
	require.Equal(t, field, errs[0].Field, "got %v", errs)
	return errs[0]
}

func requireField(t *testing.T, errs []*configcheck.Error, field string) *configcheck.Error {
	t.Helper()
	for _, e := range errs {
		if e.Field == field {
			return e
		}
	}
	require.Failf(t, "missing problem", "no problem for %q in %v", field, errs)
	return nil
}

func fieldsOf(t *testing.T, v any, o configcheck.Options) ([]configcheck.Field, []*configcheck.Error) {
	t.Helper()
	return configcheck.Fields(reflect.TypeOf(v), o)
}
