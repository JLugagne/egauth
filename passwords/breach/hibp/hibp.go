// Package hibp implements passwords.BreachChecker against the Have I Been Pwned "Pwned
// Passwords" range API using k-anonymity: the password is hashed with SHA-1, and only the first
// five hex characters of that digest are ever sent to the service. The service replies with
// every breached-password suffix sharing that prefix together with its sighting count; the
// match is resolved locally. The full password and full hash never leave the process.
//
// SHA-1 is used solely because the HIBP API is defined in terms of it; it is not a security
// choice by egauth.
//
// Failure posture: by default IsBreached returns the upstream error (network failure, non-200,
// malformed body). Wired into a passwords.Policy that propagates the error, this fails CLOSED —
// the password is rejected when the service is unreachable. Set Config.FailOpen to instead treat an
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

	"github.com/JLugagne/egauth/internal/outbound"
	"github.com/JLugagne/egauth/passwords"
)

const (
	defaultBaseURL   = "https://api.pwnedpasswords.com"
	defaultUserAgent = "egauth-hibp"
	// maxResponseBytes caps the range response. Real responses are tens of KB even with padding;
	// the cap defends against a misbehaving/hostile endpoint streaming unbounded data.
	maxResponseBytes = 4 << 20 // 4 MiB
)

// Client is a passwords.BreachChecker backed by the HIBP range API.
type Client struct {
	send      func(*http.Request) (*http.Response, error)
	baseURL   string
	userAgent string
	threshold int
	failOpen  bool
}

// Config tunes a Client. The zero value selects the public HIBP endpoint, a descriptive default
// User-Agent, a threshold of 1 and fail-closed behavior.
type Config struct {
	// BaseURL overrides the API base URL (default https://api.pwnedpasswords.com), for a
	// self-hosted mirror. A mirror is a network peer, not a trust anchor: the request still goes
	// through the guarded outbound client, so pointing this at an internal host does not make that
	// host reachable.
	BaseURL string
	// UserAgent identifies the application; HIBP requires a non-empty, descriptive value.
	UserAgent string
	// Threshold is the minimum sighting count for a password to count as breached; below 1 means 1.
	Threshold int
	// FailOpen makes IsBreached return (false, nil) instead of an error when the service is
	// unreachable or misbehaves. Without it the client fails closed.
	FailOpen bool
}

// New builds a HIBP breach-check Client that sends through the guarded outbound client: a dial-time
// guard refuses internal addresses after DNS resolution and redirects are never followed, because
// the request carries a hash prefix derived from the user's password and must not be steerable.
func New(c Config) *Client {
	cl := &Client{
		send:      outbound.New(outbound.Config{}).Static().DoSecretPath,
		baseURL:   defaultBaseURL,
		userAgent: defaultUserAgent,
		threshold: max(c.Threshold, 1),
		failOpen:  c.FailOpen,
	}
	if c.BaseURL != "" {
		cl.baseURL = strings.TrimRight(c.BaseURL, "/")
	}
	if c.UserAgent != "" {
		cl.userAgent = c.UserAgent
	}
	return cl
}

// IsBreached reports whether password appears in the HIBP corpus at least Config.Threshold times.
func (c *Client) IsBreached(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/range/"+prefix, nil)
	if err != nil {
		return c.fail(err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Add-Padding", "true")

	resp, err := c.send(req)
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
	// under the cap; this only guards a malformed/hostile endpoint (Config.BaseURL allows mirrors).
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
