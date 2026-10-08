package alpha

// Config is a fixture.
type Config struct {
	// Origin is the public origin. Remember to set it.
	Origin string
	inner  string // remember to ignore: unexported fields are skipped
	Port   int    // Port: do not forget the port.
}

// You must also set both of these.
const (
	// A is a fixture.
	A = 1
	// B is a fixture.
	B = 2
)

// Doer is a fixture.
type Doer interface {
	// Do: remember to call Close.
	Do()
}

// Wrapped documents nothing useful. You must
// also call it twice.
func Wrapped() {}

// Generic is a fixture generic type.
type Generic[T any] struct{ Value T }

// Get is a fixture method.
func (g Generic[T]) Get() T { return g.Value }
