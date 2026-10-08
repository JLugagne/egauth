package configcheck_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/configcheck"
)

type absentInner struct {
	Name    string        `egauth:"required"`
	Timeout time.Duration `egauth:"default=absent_timeout"`
}

type absentOuter struct {
	Opt    absentInner  `egauth:"optional"`
	OptPtr *absentInner `egauth:"optional"`
	Req    absentInner  `egauth:"required"`
}

type plainElem struct {
	Name string
}

type pointerElems struct {
	Items []*plainElem `egauth:"optional"`
}

func absentOptions() configcheck.Options {
	return configcheck.Options{Defaults: configcheck.Defaults{
		"absent_timeout": func(*configcheck.Resolved) any { return time.Minute },
	}}
}

func TestZeroOptionalNestedSpecIsAbsentLikeANilPointer(t *testing.T) {
	c := absentOuter{Req: absentInner{Name: "x"}}
	r, errs := configcheck.Validate(&c, absentOptions())
	require.Empty(t, errs)
	require.Equal(t, time.Minute, c.Opt.Timeout)
	v, ok := r.Get("Opt.Timeout")
	require.True(t, ok)
	require.Equal(t, time.Minute, v)
}

func TestPartlySetOptionalNestedSpecStillNeedsItsRequiredFields(t *testing.T) {
	c := absentOuter{Req: absentInner{Name: "x"}, Opt: absentInner{Timeout: time.Second}}
	_, errs := configcheck.Validate(&c, absentOptions())
	requireOnly(t, errs, "Opt.Name")

	c = absentOuter{Req: absentInner{Name: "x"}, OptPtr: &absentInner{}}
	_, errs = configcheck.Validate(&c, absentOptions())
	requireOnly(t, errs, "OptPtr.Name")
}

func TestZeroRequiredNestedSpecIsNotAbsent(t *testing.T) {
	c := absentOuter{}
	_, errs := configcheck.Validate(&c, absentOptions())
	requireOnly(t, errs, "Req.Name")
}

func TestPointerToZeroStructIsAZeroElement(t *testing.T) {
	c := pointerElems{Items: []*plainElem{{Name: "a"}, {}, nil}}
	_, errs := configcheck.Validate(&c, configcheck.Options{})
	require.ElementsMatch(t, []string{"Items[1]", "Items[2]"}, problemFields(errs))
}

func TestTenantOriginNeedsALeftmostLabelUnderAParentDomain(t *testing.T) {
	for _, o := range []string{
		"https://{tenant}",
		"https://{tenant}.com",
		"https://app.{tenant}.example.com",
		"http://{tenant}",
	} {
		c := validConfig()
		c.PublicOrigin = o
		_, errs := validate(t, &c, options())
		requireOnly(t, errs, "PublicOrigin")
	}
	for _, o := range []string{"https://{tenant}.example.com", "http://{tenant}.localhost:8080"} {
		c := validConfig()
		c.PublicOrigin = o
		_, errs := validate(t, &c, options())
		require.Empty(t, errs, o)
	}
}

func TestPredicateKindStringRoundTripsThroughParseTag(t *testing.T) {
	for k := configcheck.NonEmpty; k <= configcheck.OneOfPrimary; k++ {
		tag, err := configcheck.ParseTag("required," + k.String())
		require.NoError(t, err, k.String())
		require.Equal(t, k, tag.Predicates[0].Kind)
	}
	require.Equal(t, "bound=max", configcheck.BoundMax.String())
	require.Equal(t, "bound=le", configcheck.BoundLE.String())
	require.Equal(t, "each", configcheck.Each.String())
	require.Equal(t, "PredicateKind(0)", configcheck.PredicateKind(0).String())
	require.Equal(t, "PredicateKind(200)", configcheck.PredicateKind(200).String())
}

type hiddenInner struct {
	X string `egauth:"required"`
}

type hiddenEmbed struct {
	hiddenInner
	Y string `egauth:"optional"`
}

type hiddenField struct {
	inner hiddenInner
	Y     string `egauth:"optional"`
}

type hiddenSlice struct {
	inner []*hiddenInner
	Y     string `egauth:"optional"`
}

type deepMid struct {
	Leaf hiddenInner
}

type deepOuter struct {
	M deepMid `egauth:"optional"`
}

type specMap struct {
	M map[string]hiddenInner `egauth:"optional"`
}

func TestTagsBehindAnUnexportedFieldAreRefused(t *testing.T) {
	for name, v := range map[string]any{
		"embedded": &hiddenEmbed{},
		"field":    &hiddenField{},
		"slice":    &hiddenSlice{},
	} {
		_, errs := fieldsOf(t, v, noRegistry())
		require.NotEmpty(t, errs, name)
		_, verrs := configcheck.Validate(v, noRegistry())
		require.NotEmpty(t, verrs, name)
	}
}

func TestTagsReachableOnlyThroughAnUntaggedStructAreRefused(t *testing.T) {
	_, errs := fieldsOf(t, &deepOuter{}, noRegistry())
	requireOnly(t, errs, "M.Leaf")
}

func TestTagsBehindAMapAreRefused(t *testing.T) {
	_, errs := fieldsOf(t, &specMap{}, noRegistry())
	requireOnly(t, errs, "M")
}

func TestOriginRejectsHostsBrowsersRewrite(t *testing.T) {
	for _, o := range []string{
		"https://0x7f.1",
		"https://1.2.3",
		"https://127.1",
		"https://0177.0.0.1",
		"https://example.0x10",
		"https://example.123",
		"https://[::ffff:127.0.0.1]",
		"https://[::FFFF:7f00:1]",
		"https://[2001:db8:0:0:0:0:0:1]",
		"http://[::ffff:7f00:1]:8080",
	} {
		c := validConfig()
		c.PublicOrigin = o
		_, errs := validate(t, &c, options())
		requireOnly(t, errs, "PublicOrigin")
	}
	for _, o := range []string{"https://203.0.113.7", "https://[2001:db8::1]", "http://[::1]:8080", "https://a1.example.com"} {
		c := validConfig()
		c.PublicOrigin = o
		_, errs := validate(t, &c, options())
		require.Empty(t, errs, o)
	}
}
