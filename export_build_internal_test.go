package egauth

import (
	"net/http"
	"slices"
)

func ServedPatterns(h http.Handler) []string {
	b, ok := h.(*builtHandler)
	if !ok {
		return nil
	}
	return slices.Clone(b.patterns)
}

func MatchedPattern(h http.Handler, r *http.Request) string {
	b, ok := h.(*builtHandler)
	if !ok {
		return ""
	}
	_, p := b.mux.Handler(r)
	return p
}

func TablePatterns[C any](a *Auth[C]) []string {
	t, err := a.authTable()
	if err != nil {
		return nil
	}
	return t.Patterns(a.cfg.BasePath)
}
