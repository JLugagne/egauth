// Package redirect is the single owner of post-login redirect validation (return_to and absolute
// redirects). Parse is the only way to obtain a Target, so a value that has not been validated
// cannot reach a sealed Pending. The package depends on the standard library only.
package redirect

import (
	"errors"
	"net/url"
	"strings"
)

// MaxLength bounds the raw and the re-serialised target, in bytes, so that a sealed target always
// fits in the session cookie budget.
const MaxLength = 512

var (
	// ErrNoOrigins is returned by Parse when called with the zero Origins.
	ErrNoOrigins = errors.New("redirect: origins are required")
	// ErrInvalidOrigin is returned by NewOrigins for a value that is not an exact http(s) origin.
	ErrInvalidOrigin = errors.New("redirect: invalid origin")
	// ErrRejected is returned by Parse for every target it refuses; it is joined with a reason.
	ErrRejected = errors.New("redirect: target rejected")
)

var forbiddenEscapes = []string{"%2f", "%5c", "%09", "%0a", "%0d", "%25", "%2e"}

// Origins is the set of origins a target may point to: relative targets resolve against Public,
// absolute targets are accepted only on an exact match with one of the extra origins.
type Origins struct {
	public *url.URL
	extra  []string
}

// NewOrigins validates public (the tenant-expanded public origin) and extra (the configured
// ExtraOrigins). Each must be an exact http or https origin with no user, path, query or
// fragment; otherwise ErrInvalidOrigin is returned.
func NewOrigins(public string, extra []string) (Origins, error) {
	pu, err := parseOrigin(public)
	if err != nil {
		return Origins{}, err
	}
	o := Origins{public: pu}
	for _, e := range extra {
		eu, err := parseOrigin(e)
		if err != nil {
			return Origins{}, err
		}
		o.extra = append(o.extra, eu.Scheme+"://"+eu.Host)
	}
	return o, nil
}

func parseOrigin(raw string) (*url.URL, error) {
	if raw == "" || !printableASCII(raw) || strings.ContainsAny(raw, `\#?@`) {
		return nil, errors.Join(ErrInvalidOrigin, errors.New(raw))
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.Join(ErrInvalidOrigin, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Opaque != "" ||
		u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.Join(ErrInvalidOrigin, errors.New(raw))
	}
	u.Host = strings.ToLower(u.Host)
	return u, nil
}

// Target is a validated redirect target. The zero Target means "no target".
type Target struct {
	s string
}

// String returns the re-serialised target: a path-absolute reference on the public origin, or an
// absolute URL on an extra origin. It is empty for the zero Target.
func (t Target) String() string {
	return t.s
}

// IsZero reports whether t is the zero Target, the one Parse returns for an empty raw.
func (t Target) IsZero() bool {
	return t.s == ""
}

// Parse validates raw against origins and returns the re-serialised Target. An empty raw yields the
// zero Target and no error. Every refusal wraps ErrRejected; the zero Origins yields ErrNoOrigins.
func Parse(raw string, origins Origins) (Target, error) {
	if origins.public == nil {
		return Target{}, ErrNoOrigins
	}
	if raw == "" {
		return Target{}, nil
	}
	if err := screen(raw); err != nil {
		return Target{}, err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, errors.Join(ErrRejected, err)
	}
	if u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return Target{}, reject("user, opaque or fragment")
	}
	var out string
	if u.Scheme == "" && u.Host == "" {
		out, err = relative(u, origins.public)
	} else {
		out, err = absolute(u, origins.extra)
	}
	if err != nil {
		return Target{}, err
	}
	if len(out) > MaxLength {
		return Target{}, reject("too long")
	}
	return Target{s: out}, nil
}

func screen(raw string) error {
	if len(raw) > MaxLength {
		return reject("too long")
	}
	if !printableASCII(raw) {
		return reject("control, whitespace or non-ASCII byte")
	}
	if strings.ContainsAny(raw, `\#`) {
		return reject("backslash or fragment")
	}
	lower := strings.ToLower(raw)
	for _, esc := range forbiddenEscapes {
		if strings.Contains(lower, esc) {
			return reject("forbidden escape " + esc)
		}
	}
	for i := 0; i+2 < len(lower); i++ {
		if lower[i] == '%' && (lower[i+1] == '0' || lower[i+1] == '1' || (lower[i+1] == '7' && lower[i+2] == 'f')) {
			return reject("escaped control byte")
		}
	}
	return nil
}

func relative(u *url.URL, public *url.URL) (string, error) {
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "", reject("relative target is not path-absolute")
	}
	if hasDotSegment(u.Path) {
		return "", reject("dot segment")
	}
	r := public.ResolveReference(u)
	if r.Scheme != public.Scheme || r.Host != public.Host || r.User != nil {
		return "", reject("relative target leaves the origin")
	}
	out := r.EscapedPath()
	if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") {
		return "", reject("resolved path is not path-absolute")
	}
	if r.RawQuery != "" {
		out += "?" + r.RawQuery
	}
	return out, nil
}

func absolute(u *url.URL, extra []string) (string, error) {
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", reject("absolute target is not an http(s) URL with a host")
	}
	if hasDotSegment(u.Path) {
		return "", reject("dot segment")
	}
	origin := u.Scheme + "://" + strings.ToLower(u.Host)
	for _, e := range extra {
		if e == origin {
			out := origin + u.EscapedPath()
			if u.RawQuery != "" {
				out += "?" + u.RawQuery
			}
			return out, nil
		}
	}
	return "", reject("origin not trusted")
}

func hasDotSegment(path string) bool {
	for seg := range strings.SplitSeq(path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

func reject(reason string) error {
	return errors.Join(ErrRejected, errors.New(reason))
}
