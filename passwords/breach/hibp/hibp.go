// Package hibp implements passwords.BreachChecker against the Have I Been Pwned "Pwned
// Passwords" range API using k-anonymity: the password is hashed with SHA-1, and only the first
// five hex characters of that digest are ever sent to the service. The service replies with
// every breached-password suffix sharing that prefix together with its sighting count; the
// match is resolved locally. The full password and full hash never leave the process.
//
// SHA-1 is used solely because the HIBP API is defined in terms of it; it is not a security
// choice by libauth.
//
// Failure posture: by default IsBreached returns the upstream error (network failure, non-200,
// malformed body). Wired into a passwords.Policy that propagates the error, this fails CLOSED —
// the password is rejected when the service is unreachable. Use WithFailOpen to instead treat an
// unreachable service as "not breached" (fail open), trading screening coverage for availability.
package hibp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JLugagne/libauth/passwords"
)

const (
	defaultBaseURL   = "https://api.pwnedpasswords.com"
	defaultUserAgent = "libauth-hibp"
	defaultTimeout   = 10 * time.Second
	// maxResponseBytes caps the range response. Real responses are tens of KB even with padding;
	// the cap defends against a misbehaving/hostile endpoint streaming unbounded data.
	maxResponseBytes = 4 << 20 // 4 MiB
)

// Client is a passwords.BreachChecker backed by the HIBP range API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	userAgent  string
	threshold  int
	addPadding bool
	failOpen   bool
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client (e.g. to tune timeouts, proxies or transport). The default
// client has a 10s timeout.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		if c != nil {
			cl.httpClient = c
		}
	}
}

// WithBaseURL overrides the API base URL (default https://api.pwnedpasswords.com). Mainly for
// testing or pointing at a self-hosted mirror.
func WithBaseURL(u string) Option {
	return func(cl *Client) { cl.baseURL = strings.TrimRight(u, "/") }
}

// WithUserAgent sets the User-Agent header. HIBP requires a non-empty, descriptive User-Agent;
// set it to identify your application.
func WithUserAgent(ua string) Option {
	return func(cl *Client) {
		if ua != "" {
			cl.userAgent = ua
		}
	}
}

// WithThreshold sets the minimum sighting count for a password to be treated as breached
// (default 1, i.e. any appearance). Raise it to only reject passwords seen at least n times.
func WithThreshold(n int) Option {
	return func(cl *Client) {
		if n < 1 {
			n = 1
		}
		cl.threshold = n
	}
}

// WithAddPadding toggles the Add-Padding request header (default on). When enabled, HIBP pads
// the response with random zero-count entries so a network observer cannot infer the queried
// prefix's popularity from the response size. Zero-count entries are ignored either way.
func WithAddPadding(enabled bool) Option {
	return func(cl *Client) { cl.addPadding = enabled }
}

// WithFailOpen makes IsBreached return (false, nil) instead of an error when the service is
// unreachable or misbehaves. Without it the client fails closed (the error propagates).
func WithFailOpen() Option {
	return func(cl *Client) { cl.failOpen = true }
}

// New builds a HIBP breach-check Client.
func New(opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: defaultTimeout},
		baseURL:    defaultBaseURL,
		userAgent:  defaultUserAgent,
		threshold:  1,
		addPadding: true,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// IsBreached reports whether password appears in the HIBP corpus at least WithThreshold times.
func (c *Client) IsBreached(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/range/"+prefix, nil)
	if err != nil {
		return c.fail(err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	if c.addPadding {
		req.Header.Set("Add-Padding", "true")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return c.fail(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return c.fail(fmt.Errorf("hibp: unexpected status %d", resp.StatusCode))
	}

	// Read with a hard cap, taking one byte past it: if the body exceeds the cap it is truncated,
	// and a missing suffix in a TRUNCATED body must NOT be treated as "not breached" (that would
	// be a silent false negative — even under the fail-closed default). Surface it as an upstream
	// failure so the configured posture decides. Genuine range responses are tens of KB, well
	// under the cap; this only guards a malformed/hostile endpoint (WithBaseURL allows mirrors).
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return c.fail(err)
	}
	if int64(len(body)) > maxResponseBytes {
		return c.fail(fmt.Errorf("hibp: response exceeds %d bytes", maxResponseBytes))
	}

	count, err := scanForSuffix(bytes.NewReader(body), suffix)
	if err != nil {
		return c.fail(err)
	}
	return count >= c.threshold, nil
}

// scanForSuffix returns the sighting count for suffix in a HIBP range response (lines of
// "SUFFIX:COUNT"), or 0 if the suffix is absent. Comparison is case-insensitive.
func scanForSuffix(r io.Reader, suffix string) (int, error) {
	sc := bufio.NewScanner(r)
	// Raise the per-line cap well above bufio's 64 KiB default so a large (but within the
	// response cap) line from a misbehaving endpoint does not spuriously error — which under
	// fail-open would otherwise be swallowed into a silent false negative. The body is already
	// bounded by maxResponseBytes, so no accepted line can exceed it.
	sc.Buffer(make([]byte, 0, 64*1024), maxResponseBytes)
	for sc.Scan() {
		suf, cnt, found := strings.Cut(sc.Text(), ":")
		if !found {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(suf), suffix) {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(cnt))
		if err != nil {
			return 0, fmt.Errorf("hibp: malformed count for suffix: %w", err)
		}
		return count, nil
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("hibp: reading response: %w", err)
	}
	return 0, nil
}

// fail applies the configured failure posture: swallow (false, nil) when fail-open, else return.
func (c *Client) fail(err error) (bool, error) {
	if c.failOpen {
		return false, nil
	}
	return false, err
}

// Compile-time check that Client satisfies the hook.
var _ passwords.BreachChecker = (*Client)(nil)
