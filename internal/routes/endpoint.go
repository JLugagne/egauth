package routes

import (
	"errors"

	"github.com/JLugagne/egauth/internal/httpx"
)

var (
	// ErrUnknownPath is returned for a path outside the closed registry.
	ErrUnknownPath = errors.New("routes: unknown endpoint path")
	// ErrInvalidEndpoint is returned for an Endpoint whose Method or Meta differs from the registry,
	// or whose Func is nil.
	ErrInvalidEndpoint = errors.New("routes: invalid endpoint")
)

// Endpoint is one auth endpoint: a registered path relative to BasePath, its registry method and
// metadata, and its body. Build values with NewEndpoint; Table re-checks every field against the
// registry, so a hand-written Method or Meta is refused rather than trusted.
type Endpoint struct {
	Method string
	Path   string
	Meta   EndpointMeta
	Func   httpx.EndpointFunc
}

// NewEndpoint returns the Endpoint serving f at path with the registry's method and MetaFor(path).
// It returns ErrUnknownPath or ErrInvalidEndpoint.
func NewEndpoint(path string, f httpx.EndpointFunc) (Endpoint, error) {
	meta, ok := MetaFor(path)
	if !ok {
		return Endpoint{}, errors.Join(ErrUnknownPath, errors.New(path))
	}
	e := Endpoint{Method: Method(path), Path: path, Meta: meta, Func: f}
	return e, e.Validate()
}

// Validate reports an Endpoint that differs from the registry.
func (e Endpoint) Validate() error {
	meta, ok := MetaFor(e.Path)
	switch {
	case !ok:
		return errors.Join(ErrUnknownPath, errors.New(e.Path))
	case e.Method != Method(e.Path):
		return errors.Join(ErrInvalidEndpoint, errors.New(e.Path+": method differs from the registry"))
	case e.Meta != meta:
		return errors.Join(ErrInvalidEndpoint, errors.New(e.Path+": metadata differs from MetaFor"))
	case e.Func == nil:
		return errors.Join(ErrInvalidEndpoint, errors.New(e.Path+": nil func"))
	}
	return nil
}
