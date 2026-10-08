// Package breach describes breach-corpus lookups as value specs. A Spec holds no HTTP client: egauth
// resolves it at construction and sends its requests through the library's guarded outbound client
// (SSRF dial guard, no redirects, fixed timeouts), so no integrator transport ever carries a
// password-derived value.
package breach

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	hibpRangeURL     = "https://api.pwnedpasswords.com/range/"
	userAgent        = "egauth-breach"
	prefixLen        = 5
	suffixLen        = 2*sha1.Size - prefixLen
	maxResponseBytes = 4 << 20
)

var (
	// ErrUnresolved is returned when a Spec is used directly as a passwords.BreachChecker, or when
	// the zero Spec is queried. A Spec never fetches on its own, so it fails closed.
	ErrUnresolved = errors.New("breach: spec is resolved by egauth and never fetches on its own")
	// ErrLookup is returned by Query.Breached for an unusable answer: no response, a status other
	// than 200, a body over 4 MiB or a malformed line. The caller fails closed.
	ErrLookup = errors.New("breach: lookup failed")
)

// Spec is a k-anonymity range lookup: only the first five hex characters of the password's SHA-1
// leave the process, and the match is resolved locally. The zero Spec is invalid.
type Spec struct {
	rangeURL string
}

// HIBP is the Have I Been Pwned "Pwned Passwords" range API, queried with response padding.
func HIBP() Spec {
	return Spec{rangeURL: hibpRangeURL}
}

// IsZero reports whether s did not come from a constructor of this package.
func (s Spec) IsZero() bool { return s.rangeURL == "" }

// IsBreached always returns ErrUnresolved: set the Spec as PasswordModule.Breach and egauth performs
// the lookup through its outbound client.
func (s Spec) IsBreached(context.Context, string) (bool, error) {
	return false, ErrUnresolved
}

// Query is one prepared range lookup. Its request path carries a password-derived prefix, so it
// must be sent through a client that keeps the path out of logs and traces.
type Query struct {
	req    *http.Request
	suffix string
}

// Query prepares the lookup of password. It returns ErrUnresolved for the zero Spec.
func (s Spec) Query(ctx context.Context, password string) (Query, error) {
	if s.rangeURL == "" {
		return Query{}, ErrUnresolved
	}
	sum := sha1.Sum([]byte(password))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.rangeURL+full[:prefixLen], nil)
	if err != nil {
		return Query{}, errors.Join(ErrLookup, err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Add-Padding", "true")
	return Query{req: req, suffix: full[prefixLen:]}, nil
}

// Lookup runs the whole range lookup of password: it prepares the Query, sends its request with
// send and reads the answer with Breached. send must be a client that keeps the request path out of
// logs and traces, such as egauth's outbound DoSecretPath. A send error is joined with ErrLookup, so
// every failure fails closed.
func (s Spec) Lookup(ctx context.Context, password string, send func(*http.Request) (*http.Response, error)) (bool, error) {
	q, err := s.Query(ctx, password)
	if err != nil {
		return false, err
	}
	if send == nil {
		return false, errors.Join(ErrLookup, errors.New("nil sender"))
	}
	resp, err := send(q.Request())
	if err != nil {
		return false, errors.Join(ErrLookup, err)
	}
	return q.Breached(resp)
}

// Request returns the request to send.
func (q Query) Request() *http.Request { return q.req }

// Breached reads resp, the answer to Request, and reports whether the password was seen at least
// once; zero-count padding entries never match. It closes the body and returns ErrLookup for an
// unusable answer, including any line that is not a 35-hex-digit suffix and a non-negative count.
func (q Query) Breached(resp *http.Response) (bool, error) {
	if resp == nil || resp.Body == nil {
		return false, errors.Join(ErrLookup, errors.New("no response"))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, errors.Join(ErrLookup, errors.New("status "+strconv.Itoa(resp.StatusCode)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return false, errors.Join(ErrLookup, err)
	}
	if len(body) > maxResponseBytes {
		return false, errors.Join(ErrLookup, errors.New("response too large"))
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), maxResponseBytes)
	breached := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		suffix, n, err := parseLine(line)
		if err != nil {
			return false, errors.Join(ErrLookup, err)
		}
		if n > 0 && strings.EqualFold(suffix, q.suffix) {
			breached = true
		}
	}
	if err := sc.Err(); err != nil {
		return false, errors.Join(ErrLookup, err)
	}
	return breached, nil
}

func parseLine(line string) (string, int, error) {
	suffix, count, ok := strings.Cut(line, ":")
	suffix = strings.TrimSpace(suffix)
	if !ok || len(suffix) != suffixLen {
		return "", 0, errors.New("malformed line")
	}
	if strings.IndexFunc(suffix, notHex) >= 0 {
		return "", 0, errors.New("malformed suffix")
	}
	n, err := strconv.Atoi(strings.TrimSpace(count))
	if err != nil || n < 0 {
		return "", 0, errors.New("malformed count")
	}
	return suffix, n, nil
}

func notHex(r rune) bool {
	return (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F')
}
