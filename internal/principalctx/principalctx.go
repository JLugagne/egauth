// Package principalctx owns the one context slot that carries the request principal. It is the only
// caller of context.WithValue and Context.Value for the principal (G6), and it exposes no public
// accessor: handlers receive the principal as an argument, and the slot exists so that library code
// deep in a call chain can tell a request apart from background work (InRequest).
package principalctx

import "context"

type slot struct{}

type held struct {
	v any
}

// Set returns a context whose slot holds p, replacing any principal already held: the slot is single,
// whatever the type of p. The route layer must call it for every served request, anonymous ones
// included, so that InRequest is reliable. A nil ctx is treated as context.Background().
func Set[P any](ctx context.Context, p P) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, slot{}, held{v: p})
}

// Get returns the principal held by ctx when it has type P. It reports false for a nil ctx, an empty
// slot or a principal of another type.
func Get[P any](ctx context.Context) (P, bool) {
	var zero P
	if ctx == nil {
		return zero, false
	}
	h, ok := ctx.Value(slot{}).(held)
	if !ok {
		return zero, false
	}
	p, ok := h.v.(P)
	if !ok {
		return zero, false
	}
	return p, true
}

// InRequest reports whether ctx descends from a served request, whatever principal it holds. The
// facades use it to refuse a System caller inside a request.
func InRequest(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	_, ok := ctx.Value(slot{}).(held)
	return ok
}
