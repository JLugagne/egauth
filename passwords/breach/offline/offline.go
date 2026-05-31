// Package offline implements passwords.BreachChecker against an in-memory set of known-
// compromised password SHA-1 hashes loaded once at startup (for example from the downloadable
// HIBP "Pwned Passwords" offline corpus, or a custom blocklist). It makes no network calls, so
// it suits air-gapped deployments and serves as a fail-safe screen behind, or instead of, the
// online hibp client.
//
// SHA-1 is used solely to match the HIBP corpus format; it is not a security choice. Candidate
// passwords are hashed locally and looked up in the set — no secret is stored in plaintext.
package offline

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/JLugagne/egauth/passwords"
)

// Checker reports a password as breached when its uppercase-hex SHA-1 is in the loaded set.
type Checker struct {
	hashes map[string]struct{} // uppercase hex SHA-1 digests
}

// Option configures a load.
type Option func(*loadConfig)

type loadConfig struct {
	threshold int
}

// WithThreshold sets the minimum sighting count a "<hash>:<count>" entry must have to be loaded
// as breached (default 1). Entries without a count are always loaded. Has no effect on
// LoadPasswords (plaintext lists carry no counts).
func WithThreshold(n int) Option {
	return func(c *loadConfig) {
		if n < 1 {
			n = 1
		}
		c.threshold = n
	}
}

func newChecker() *Checker { return &Checker{hashes: make(map[string]struct{})} }

// LoadHashes builds a Checker from newline-delimited SHA-1 hashes. Each line is either a bare
// 40-char hex hash or the HIBP offline format "<HASH>:<count>"; counts below WithThreshold are
// skipped. Blank lines are ignored. Hashes are normalized to uppercase. A line that is neither
// blank nor a valid hash is an error.
func LoadHashes(r io.Reader, opts ...Option) (*Checker, error) {
	cfg := loadConfig{threshold: 1}
	for _, opt := range opts {
		opt(&cfg)
	}

	c := newChecker()
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		hashPart := line
		if h, cnt, found := strings.Cut(line, ":"); found {
			count, err := strconv.Atoi(strings.TrimSpace(cnt))
			if err != nil {
				return nil, fmt.Errorf("offline: malformed count in %q: %w", line, err)
			}
			if count < cfg.threshold {
				continue
			}
			hashPart = strings.TrimSpace(h)
		}
		norm, err := normalizeHash(hashPart)
		if err != nil {
			return nil, err
		}
		c.hashes[norm] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("offline: reading hashes: %w", err)
	}
	return c, nil
}

// LoadPasswords builds a Checker from a newline-delimited list of plaintext secrets, hashing
// each. Lines are trimmed of surrounding whitespace; blank lines are ignored.
func LoadPasswords(r io.Reader) (*Checker, error) {
	c := newChecker()
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		pw := strings.TrimSpace(sc.Text())
		if pw == "" {
			continue
		}
		c.hashes[hashUpper(pw)] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("offline: reading passwords: %w", err)
	}
	return c, nil
}

// IsBreached reports whether password's SHA-1 is in the loaded set. It never returns an error.
func (c *Checker) IsBreached(_ context.Context, password string) (bool, error) {
	_, ok := c.hashes[hashUpper(password)]
	return ok, nil
}

func hashUpper(password string) string {
	sum := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// normalizeHash validates a 40-char hex SHA-1 and returns it uppercased.
func normalizeHash(s string) (string, error) {
	if len(s) != 40 {
		return "", fmt.Errorf("offline: invalid SHA-1 hash %q: want 40 hex chars", s)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("offline: invalid SHA-1 hash %q: %w", s, err)
	}
	return strings.ToUpper(s), nil
}

// Compile-time check that Checker satisfies the hook.
var _ passwords.BreachChecker = (*Checker)(nil)
