package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"strings"
	"unicode"
)

// recoveryCodeBytes is the entropy per recovery code (80 bits → 16 base32 chars).
const recoveryCodeBytes = 10

// HashRecoveryCode normalizes a recovery code (strips separators/whitespace, uppercases) and
// returns its hex-encoded SHA-256. Only this hash is stored; the plaintext is shown once at
// generation. Normalization lets a user re-enter the code with or without the display dashes.
func HashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

func normalizeRecoveryCode(code string) string {
	var b strings.Builder
	for _, r := range code {
		if r == '-' || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

// generateRecoveryCodes mints n single-use recovery codes, returning the human-facing
// plaintext (grouped with dashes for readability) and the corresponding stored hashes (in the
// same order).
func generateRecoveryCodes(n int) (plaintext, hashes []string, err error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	plaintext = make([]string, 0, n)
	hashes = make([]string, 0, n)
	for range n {
		b := make([]byte, recoveryCodeBytes)
		if _, err = rand.Read(b); err != nil {
			return nil, nil, err
		}
		raw := enc.EncodeToString(b) // 16 chars
		code := groupCode(raw, 4)    // e.g. ABCD-EFGH-IJKL-MNOP
		plaintext = append(plaintext, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return plaintext, hashes, nil
}

// groupCode inserts a dash every size characters for readability.
func groupCode(s string, size int) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%size == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}
