package egauth

import "errors"

var ErrNo = errors.New("service not configured")

var ErrMis = errors.New("Misconfigured thing")

var ErrNoX = errors.New("no database configured yet")

var Fine = errors.New("something else entirely")

type Holder struct {
	Err error
	Ok  int
}

type holderPrivate struct {
	Err error
}

type MyErr struct {
	Err error
}

func (e *MyErr) Error() string { return "my" }

func MustParse(s string) int { return len(s) }

type Policy struct{}

func (Policy) MustChange() bool { return false }

func MustBe() bool { return false }

func Boom() {
	panic("x")
}

func Nested() {
	f := func() { panic("y") }
	f()
}

func quiet() {
	panic("z")
}

func Calm() int {
	_ = holderPrivate{}
	quiet()
	return 1
}
