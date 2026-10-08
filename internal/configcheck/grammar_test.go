package configcheck_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/configcheck"
)

func TestParseTagAcceptsTheGrammar(t *testing.T) {
	tag, err := configcheck.ParseTag("required,nonempty,each=token")
	require.NoError(t, err)
	require.Equal(t, configcheck.Required, tag.Requirement)
	require.Len(t, tag.Predicates, 2)
	require.Equal(t, configcheck.NonEmpty, tag.Predicates[0].Kind)
	require.Equal(t, configcheck.Each, tag.Predicates[1].Kind)
	require.Equal(t, configcheck.Token, tag.Predicates[1].Elem.Kind)

	tag, err = configcheck.ParseTag("default=idle_timeout,bound=le:MaxLifetime")
	require.NoError(t, err)
	require.Equal(t, configcheck.Defaulted, tag.Requirement)
	require.Equal(t, "idle_timeout", tag.Default)
	require.Equal(t, configcheck.BoundLE, tag.Predicates[0].Kind)
	require.Equal(t, "MaxLifetime", tag.Predicates[0].Ref)

	tag, err = configcheck.ParseTag("default=max_lifetime,bound=max:2160h")
	require.NoError(t, err)
	require.Equal(t, configcheck.BoundMax, tag.Predicates[0].Kind)
	require.Equal(t, 2160*time.Hour, tag.Predicates[0].Max)

	tag, err = configcheck.ParseTag("module=Password|LoginCode.Email")
	require.NoError(t, err)
	require.Equal(t, configcheck.ModuleDependent, tag.Requirement)
	require.Equal(t, []string{"Password", "LoginCode.Email"}, tag.Modules)

	for _, raw := range []string{
		"optional", "optional,each=origin", "required,origin", "default=basepath,path",
		"required,oneof_primary", "optional,each=provider", "required,each=external",
		"optional,each=bound=max:1h",
	} {
		_, err := configcheck.ParseTag(raw)
		require.NoError(t, err, raw)
	}
}

func TestParseTagRejectsBadGrammar(t *testing.T) {
	bad := []string{
		"",
		"nonempty",
		"required,optional",
		"required,default=x",
		"default=x,module=Password",
		"required,required",
		"required,nonempty,nonempty",
		"required,unknown",
		"required, origin",
		"Required",
		"default=",
		"default=Bad-Key",
		"module=",
		"module=Password|",
		"module=password",
		"module=Password|Password",
		"module=Login..Code",
		"required,each=",
		"required,each=each=token",
		"required,each=oneof_primary",
		"required,each=unknown",
		"required,each=token,each=origin",
		"required,bound=max:",
		"required,bound=max:abc",
		"required,bound=max:-1h",
		"required,bound=max:0s",
		"required,bound=le:",
		"required,bound=le:lower",
		"required,bound=min:1h",
		"required,bound=max:1h,bound=max:2h",
		"required,origin=x",
		",required",
		"required,",
	}
	for _, raw := range bad {
		_, err := configcheck.ParseTag(raw)
		require.ErrorIs(t, err, configcheck.ErrGrammar, "%q", raw)
	}
}

func TestFieldsListsEveryTaggedField(t *testing.T) {
	fields, errs := fieldsOf(t, config{}, options())
	require.Empty(t, errs)
	paths := make([]string, 0, len(fields))
	for _, f := range fields {
		paths = append(paths, f.Path)
	}
	require.ElementsMatch(t, []string{
		"PublicOrigin", "BasePath", "ExtraOrigins", "Storage", "Storage.Identity", "Storage.Tokens",
		"Storage.Federation", "Email", "Policy", "Policy.IdleTimeout", "Policy.MaxLifetime",
		"Policy.RecheckEvery", "Modules", "Modules.Password.Registration", "Modules.Passkey.DisplayName",
		"Modules.OAuth.Providers", "Modules.External.Factors", "Modules.APIKeys.Kinds",
		"Modules.APIKeys.Prefix", "Issuer",
	}, paths)
	for _, f := range fields {
		if f.Path == "Policy.MaxLifetime" {
			require.Equal(t, configcheck.Defaulted, f.Tag.Requirement)
			require.Equal(t, "max_lifetime", f.Tag.Default)
		}
	}
}

func TestFieldsAcceptsAPointerType(t *testing.T) {
	_, errs := fieldsOf(t, &config{}, options())
	require.Empty(t, errs)
}

type unknownKey struct {
	A string `egauth:"required,shiny"`
}

type missingRequirement struct {
	A string `egauth:"origin"`
}

type untagged struct {
	A string `egauth:"required"`
	B string
	C bool
}

type taggedUnexported struct {
	A string `egauth:"required"`
	b string `egauth:"required"`
}

type unresolvedModule struct {
	A       string  `egauth:"module=Nope"`
	Modules modules `egauth:"required,oneof_primary"`
}

type unresolvedNestedModule struct {
	A       string  `egauth:"module=LoginCode.Fax"`
	Modules modules `egauth:"required,oneof_primary"`
}

type moduleLeafNotAToggle struct {
	A       string  `egauth:"module=Password.Registration"`
	Modules modules `egauth:"required,oneof_primary"`
}

type ambiguousModule struct {
	A       string  `egauth:"module=Password"`
	Modules modules `egauth:"required,oneof_primary"`
}

type unresolvedBoundRef struct {
	A time.Duration `egauth:"optional,bound=le:Missing"`
}

type boundRefNotDuration struct {
	A time.Duration `egauth:"optional,bound=le:B"`
	B string        `egauth:"optional"`
}

type boundOnString struct {
	A string `egauth:"optional,bound=max:1h"`
}

type originOnInt struct {
	A int `egauth:"optional,origin"`
}

type nonemptyOnInt struct {
	A int `egauth:"optional,nonempty"`
}

type eachOnString struct {
	A string `egauth:"optional,each=token"`
}

type eachKindMismatch struct {
	A []int `egauth:"optional,each=origin"`
}

type oneofElsewhere struct {
	A       string  `egauth:"required,oneof_primary"`
	Modules modules `egauth:"required"`
}

type unknownDefault struct {
	A string `egauth:"default=nowhere"`
}

type providerField struct {
	A []provider `egauth:"optional,each=provider"`
}

type externalField struct {
	A []externalFactor `egauth:"optional,each=external"`
}

type durationField struct {
	A time.Duration `egauth:"optional,bound=max:1h"`
}

func TestFieldsRejectsBrokenSpecs(t *testing.T) {
	cases := map[string]struct {
		v     any
		o     func() configcheck.Options
		field string
	}{
		"unknown key":               {unknownKey{}, noRegistry, "A"},
		"missing requirement":       {missingRequirement{}, noRegistry, "A"},
		"untagged field":            {untagged{}, noRegistry, "B"},
		"tag on unexported field":   {taggedUnexported{}, noRegistry, "b"},
		"unresolved module":         {unresolvedModule{}, modulesOnly, "A"},
		"unresolved nested module":  {unresolvedNestedModule{}, modulesOnly, "A"},
		"module leaf not a toggle":  {moduleLeafNotAToggle{}, modulesOnly, "A"},
		"module without modules":    {unresolvedModule{}, noRegistry, "A"},
		"ambiguous module switch":   {ambiguousModule{}, ambiguousSwitch, "A"},
		"unresolved bound ref":      {unresolvedBoundRef{}, noRegistry, "A"},
		"bound ref not a duration":  {boundRefNotDuration{}, noRegistry, "A"},
		"bound on string":           {boundOnString{}, noRegistry, "A"},
		"origin on int":             {originOnInt{}, noRegistry, "A"},
		"nonempty on int":           {nonemptyOnInt{}, noRegistry, "A"},
		"each on string":            {eachOnString{}, noRegistry, "A"},
		"each element mismatch":     {eachKindMismatch{}, noRegistry, "A[]"},
		"oneof_primary elsewhere":   {oneofElsewhere{}, modulesOnly, "A"},
		"unknown default key":       {unknownDefault{}, noRegistry, "A"},
		"provider without function": {providerField{}, noRegistry, "A[]"},
		"external without function": {externalField{}, noRegistry, "A[]"},
		"raised bound not a bound":  {durationField{}, raisedElsewhere, "Nope"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, errs := fieldsOf(t, tc.v, tc.o())
			requireField(t, errs, tc.field)
		})
	}
}

func TestFieldsRejectsUnusedRegistryKeys(t *testing.T) {
	o := options()
	o.Defaults["orphan"] = func(*configcheck.Resolved) any { return "x" }
	_, errs := fieldsOf(t, config{}, o)
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Problem, "orphan")
}

func TestFieldsRejectsPrimaryPathsThatDoNotResolve(t *testing.T) {
	o := options()
	o.Primary = append(o.Primary, "Telepathy")
	_, errs := fieldsOf(t, config{}, o)
	requireField(t, errs, "Modules")

	o = options()
	o.Primary = nil
	_, errs = fieldsOf(t, config{}, o)
	requireField(t, errs, "Modules")
}

func TestFieldsRejectsAModulesPathThatDoesNotResolve(t *testing.T) {
	o := options()
	o.Modules = "Mods"
	_, errs := fieldsOf(t, config{}, o)
	require.NotEmpty(t, errs)
}

func TestValidateRefusesBrokenSpecsBeforeTouchingTheValue(t *testing.T) {
	v := unknownKey{}
	r, errs := configcheck.Validate(&v, noRegistry())
	require.Nil(t, r)
	requireOnly(t, errs, "A")

	c := validConfig()
	o := options()
	o.Defaults["orphan"] = func(*configcheck.Resolved) any { return "x" }
	_, errs = validate(t, &c, o)
	require.Len(t, errs, 1)
	require.Empty(t, c.BasePath, "no default is applied when the spec is broken")
}

func TestFieldsIgnoresStructsWithoutTags(t *testing.T) {
	type opaque struct {
		Untagged string
	}
	type holder struct {
		O opaque `egauth:"optional"`
	}
	fields, errs := fieldsOf(t, holder{}, noRegistry())
	require.Empty(t, errs)
	require.Len(t, fields, 1)
}

func TestRecursiveTypesTerminate(t *testing.T) {
	type node struct {
		Name string `egauth:"required"`
		Next []node `egauth:"optional"`
	}
	_, errs := fieldsOf(t, node{}, noRegistry())
	require.Empty(t, errs)
	v := node{Name: "a", Next: []node{{Name: "b"}, {Next: []node{{Name: "c"}}}}}
	_, verrs := configcheck.Validate(&v, noRegistry())
	requireOnly(t, verrs, "Next[1].Name")
}

func noRegistry() configcheck.Options { return configcheck.Options{} }

func modulesOnly() configcheck.Options {
	return configcheck.Options{Modules: "Modules", Primary: []string{"Password"}}
}

func ambiguousSwitch() configcheck.Options {
	o := modulesOnly()
	o.Switches = map[string]bool{"Password": true}
	return o
}

func raisedElsewhere() configcheck.Options {
	return configcheck.Options{Raised: map[string]time.Duration{"Nope": time.Hour}}
}
