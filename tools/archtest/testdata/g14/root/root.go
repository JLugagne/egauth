package egauth

import (
	"errors"
	"fmt"
	"net/http"
)

type custom interface{ Timeout() bool }

func Sniff(v any) string {
	if s, ok := v.(fmt.Stringer); ok {
		return s.String()
	}
	return ""
}

func Concrete(v any) string {
	s, _ := v.(string)
	return s
}

func Switch(v any) int {
	switch v.(type) {
	case error:
		return 1
	case string:
		return 2
	}
	return 0
}

func Flush(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func Target(err error) bool {
	var c custom
	return errors.As(err, &c)
}

func ConcreteTarget(err error) bool {
	var e *myErr
	return errors.As(err, &e)
}

type myErr struct{}

func (*myErr) Error() string { return "" }

func Generic[T any](v any) bool {
	_, ok := v.(T)
	return ok
}
