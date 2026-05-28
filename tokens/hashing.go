package tokens

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashToken computes the SHA-256 hash of a token and returns it as a hex-encoded string.
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
