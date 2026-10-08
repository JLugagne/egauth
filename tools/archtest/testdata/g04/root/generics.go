package egauth

import "sync/atomic"

type Res[T any] struct{ V T }

func NewRes() Res[error] { return Res[error]{} }

type Opt[T any] struct{ V T }

func NewOpt() Opt[int] { return Opt[int]{} }

type Last struct{ P *atomic.Pointer[error] }

func NewLast() Last { return Last{} }
