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
	"errors"
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
// A range response is read up to 1 MiB; a longer one is an upstream failure handled by the
// configured failure posture, never a "not breached" answer from a truncated body.
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

func scanForSuffix(r io.Reader, suffix string) (int, error) {
	sc := bufio.NewScanner(r)
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
			return 0, errors.Join(errors.New("hibp: malformed count for suffix"), err)
		}
		return count, nil
	}
	if err := sc.Err(); err != nil {
		return 0, errors.Join(errors.New("hibp: reading response"), err)
	}
	return 0, nil
}

func (c *Client) fail(err error) (bool, error) {
	if c.failOpen {
		return false, nil
	}
	return false, err
}

// Compile-time check that Client satisfies the hook.
var _ passwords.BreachChecker = (*Client)(nil)
