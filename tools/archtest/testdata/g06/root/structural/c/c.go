package c

import (
	"context"
	"net/http"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/event"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/internal/session"
)

type valuer interface{ Value(key any) any }

type former interface{ FormValue(key string) string }

type starter interface{ Start() }

type emitter interface{ Emit(name string) }

func Values(ctx context.Context) {
	var v valuer = ctx
	_ = v.Value("k")
}

func Forms(r *http.Request) {
	var f former = r
	_ = f.FormValue("x")
}

func Starts(b session.Backend) {
	var s starter = b
	s.Start()
}

func Emits(s event.Sink) map[string]emitter { return map[string]emitter{"x": s} }

func Asserted(x any) {
	if v, ok := x.(valuer); ok {
		_ = v.Value("k")
	}
}

func Switched(x any) {
	switch s := x.(type) {
	case starter:
		s.Start()
	}
}

func Plain(ctx context.Context) context.Context { return ctx }
