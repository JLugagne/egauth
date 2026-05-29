package otp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
)

// generateCode returns a uniformly-random numeric code of the given number of digits,
// zero-padded (e.g. "004217"). It uses crypto/rand with rejection-free big.Int sampling, so
// there is no modulo bias.
func generateCode(digits int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", digits, n), nil
}

// HashCode returns the hex-encoded SHA-256 of a code. Only this hash is persisted.
//
// Note: numeric OTPs are low-entropy by design, so the at-rest hash is not a meaningful
// barrier against an attacker who has already exfiltrated the database — the real protection
// is the short TTL, single-use consumption and the attempt limit. See SECURITY.md.
func HashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// compareCode reports whether code matches the stored hash, in constant time.
func compareCode(codeHash, code string) bool {
	got := HashCode(code)
	return subtle.ConstantTimeCompare([]byte(got), []byte(codeHash)) == 1
}
