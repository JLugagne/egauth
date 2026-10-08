package egauth

var MustParseVar = func(s string) int { return len(s) }

var MustOK = func() bool { return true }

var BoomVar = func() { panic("x") }

var Built = struct{ Hook func() }{Hook: func() { panic("y") }}

var calmVar = func() { panic("z") }

var Pair, pairHidden = func() { panic("a") }, func() { panic("b") }

type MustFunc func() int

var MustNamed MustFunc

var MustFlag = true

type Getter interface {
	MustGet() int
	MustHave() bool
	Get() int
}

type Hooks struct {
	MustRun   func() error
	MustCheck func() bool
	mustHide  func() int
}
