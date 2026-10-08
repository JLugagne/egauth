package egauth

import (
	"net/http"
	"sync/atomic"
)

type Getter[T any] interface{ Get() T }

func NewGetter() Getter[http.Handler] { return nil }

type Box[T any] struct{ V T }

func NewBox() Box[http.Handler] { return Box[http.Handler]{} }

type Pair[T any] struct{ A, B T }

func NewPair() *Pair[http.HandlerFunc] { return nil }

type Slot struct{ Cur *atomic.Pointer[http.Handler] }

func NewSlot() Slot { return Slot{} }

var Current atomic.Pointer[http.Handler]

type Safe[T any] struct{ V T }

func NewSafe() Safe[string] { return Safe[string]{} }

var Count atomic.Pointer[string]
