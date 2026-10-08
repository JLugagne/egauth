package egauth

import (
	"errors"
	"fmt"
	"net/http"
)

type timeoutErr interface {
	error
	Timeout() bool
}

func as[T any](v any) (T, bool) {
	t, ok := v.(T)
	return t, ok
}

func SniffGeneric(w http.ResponseWriter) bool {
	_, ok := as[custom](w)
	return ok
}

func viaChain[T any](v any) bool {
	_, ok := as[T](v)
	return ok
}

func SniffChain(v any) bool { return viaChain[fmt.Stringer](v) }

func ConcreteGeneric(v any) bool {
	_, ok := as[string](v)
	return ok
}

func ConcreteChain(v any) bool { return viaChain[int](v) }

type box[T any] struct{}

func (box[T]) get(v any) (T, bool) {
	t, ok := v.(T)
	return t, ok
}

func SniffBox(v any) bool {
	_, ok := box[fmt.Stringer]{}.get(v)
	return ok
}

func switcher[T any](v any) bool {
	switch v.(type) {
	case T:
		return true
	}
	return false
}

func SniffSwitch(v any) bool { return switcher[custom](v) }

func asTarget[T any](err error) bool {
	var t T
	return errors.As(err, &t)
}

func SniffAsTarget(err error) bool { return asTarget[custom](err) }

func SniffAsType(err error) bool {
	_, ok := errors.AsType[timeoutErr](err)
	return ok
}

func ConcreteAsType(err error) bool {
	_, ok := errors.AsType[*myErr](err)
	return ok
}

func passThrough[T any](v T) T { return v }

func NoAssert(v fmt.Stringer) fmt.Stringer { return passThrough[fmt.Stringer](v) }
