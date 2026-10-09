package mfasvc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"strings"
	"unicode"
)

const (
	recoveryCodeBytes = 10
	recoveryGroup     = 4
	maxRecoveryInput  = 64
)

func newRecoveryCodes() ([]string, []string, error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	plain := make([]string, 0, RecoveryCodeCount)
	hashes := make([]string, 0, RecoveryCodeCount)
	seen := map[string]bool{}
	for len(plain) < RecoveryCodeCount {
		b := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		code := group(enc.EncodeToString(b))
		h := hashRecoveryCode(code)
		if seen[h] {
			continue
		}
		seen[h] = true
		plain = append(plain, code)
		hashes = append(hashes, h)
	}
	return plain, hashes, nil
}

func group(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%recoveryGroup == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
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

func hashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}
