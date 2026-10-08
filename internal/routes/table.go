package routes

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/JLugagne/egauth/internal/httpx"
)

var (
	// ErrConflict is returned when two endpoints or declarations claim overlapping patterns.
	ErrConflict = errors.New("routes: conflicting routes")
	// ErrInvalidBasePath is returned for a BasePath that does not start with '/', ends with '/',
	// carries a pattern wildcard, a space or a control byte, or an empty, "." or ".." segment
	// (the mux cleans request paths, so endpoints under such a base would be unreachable).
	ErrInvalidBasePath = errors.New("routes: invalid base path")
)

// Table is the validated set of auth endpoints of one deployment. The zero Table is empty.
type Table struct {
	eps []Endpoint
}

// NewTable validates every endpoint against the registry and refuses two endpoints on one path.
// It returns every problem joined (ErrUnknownPath, ErrInvalidEndpoint, ErrConflict).
func NewTable(eps ...Endpoint) (Table, error) {
	var errs []error
	seen := map[string]bool{}
	for _, e := range eps {
		if err := e.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		if seen[e.Path] {
			errs = append(errs, errors.Join(ErrConflict, errors.New(e.Path+" declared twice")))
			continue
		}
		seen[e.Path] = true
	}
	if len(errs) > 0 {
		return Table{}, errors.Join(errs...)
	}
	sorted := slices.Clone(eps)
	slices.SortFunc(sorted, func(a, b Endpoint) int { return strings.Compare(a.Path, b.Path) })
	return Table{eps: sorted}, nil
}

// Endpoints returns a copy of the endpoints, ordered by path.
func (t Table) Endpoints() []Endpoint {
	return slices.Clone(t.eps)
}

// ValidateBasePath reports a BasePath that cannot prefix the registry paths.
func ValidateBasePath(basePath string) error {
	if !strings.HasPrefix(basePath, "/") || strings.HasSuffix(basePath, "/") || strings.ContainsAny(basePath, "{} \t\r\n?#%") {
		return errors.Join(ErrInvalidBasePath, errors.New(basePath))
	}
	for seg := range strings.SplitSeq(basePath[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return errors.Join(ErrInvalidBasePath, errors.New(basePath))
		}
	}
	return nil
}

// Patterns returns the ServeMux pattern of every endpoint under basePath, ordered by path.
func (t Table) Patterns(basePath string) []string {
	out := make([]string, 0, len(t.eps))
	for _, e := range t.eps {
		out = append(out, e.Method+" "+basePath+e.Path)
	}
	return out
}

// Mount registers every endpoint on mux under basePath behind p. It returns ErrInvalidBasePath,
// httpx.ErrInvalidMeta, or ErrConflict when mux already holds a conflicting pattern; endpoints
// registered before a failure stay registered, so callers mount on a mux they discard on error.
func (t Table) Mount(mux *http.ServeMux, basePath string, p *httpx.Preamble) error {
	if err := ValidateBasePath(basePath); err != nil {
		return err
	}
	if p == nil {
		return errors.Join(httpx.ErrInvalidMeta, errors.New("nil preamble"))
	}
	for _, e := range t.eps {
		h, err := p.Wrap(e.Path, e.Meta, e.Func)
		if err != nil {
			return err
		}
		if err := register(mux, e.Method+" "+basePath+e.Path, h); err != nil {
			return err
		}
	}
	return nil
}

func register(mux *http.ServeMux, pattern string, h http.Handler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Join(ErrConflict, errors.New(pattern+": "+fmt.Sprint(r)))
		}
	}()
	mux.Handle(pattern, h)
	return nil
}
