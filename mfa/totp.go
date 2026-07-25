package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// secretBytes is the entropy of a TOTP shared secret (160 bits, the SHA-1 block-aligned size
// recommended by RFC 4226).
const secretBytes = 20

// MinSecretBytes is the smallest DECODED shared-secret length accepted anywhere a secret is used:
// 128 bits, the minimum RFC 4226 §4 R6 mandates (it recommends the 160 bits GenerateSecret
// produces). Anything shorter is rejected with ErrWeakSecret rather than used as an HMAC key — an
// empty secret would key the HMAC with zero bytes, making every code it produces computable by
// anyone and turning the second factor into a no-op.
const MinSecretBytes = 16

// ValidateSecret checks that secret is a usable TOTP shared secret — valid base32 (padded or not,
// spaces tolerated) decoding to at least MinSecretBytes bytes — returning nil when it is,
// ErrWeakSecret when it is well-formed but too short, and a decoding error otherwise. Call it when
// importing or migrating enrollments minted outside this package; EnrollTOTP, ConfirmTOTP,
// VerifyTOTP and GenerateCode already enforce it.
func ValidateSecret(secret string) error {
	_, err := decodeSecret(secret)
	return err
}

// GenerateSecret returns a fresh base32-encoded (RFC 4648, no padding, uppercase) TOTP shared
// secret suitable for provisioning into an authenticator app.
func GenerateSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// ProvisioningURI builds the otpauth:// URI an authenticator app consumes (typically via a QR
// code). issuer and account name the credential in the app; digits/period must match what
// VerifyTOTP uses. The algorithm is fixed to SHA1, which authenticator apps universally
// support.
func ProvisioningURI(secret, issuer, account string, digits int, period time.Duration) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", strconv.Itoa(digits))
	v.Set("period", strconv.Itoa(int(period.Seconds())))
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// GenerateCode returns the TOTP code the authenticator app would display for the secret at the
// given instant. It is primarily useful for tooling and tests; servers verify with VerifyTOTP.
func GenerateCode(secret string, at time.Time, digits int, period time.Duration) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, uint64(timeStep(at, period)), digits), nil
}

// decodeSecret decodes a base32 secret tolerantly: it strips spaces, uppercases, and pads to a
// multiple of 8 so both padded and unpadded forms decode. It returns ErrWeakSecret when the decoded
// key is shorter than MinSecretBytes, so no caller can ever key an HMAC with a truncated (or empty)
// shared secret.
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(key) < MinSecretBytes {
		return nil, ErrWeakSecret
	}
	return key, nil
}

// hotp computes the RFC 4226 HOTP value for a counter, zero-padded to digits.
func hotp(key []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3).
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	mod := bin % uint32(pow10(digits))
	return fmt.Sprintf("%0*d", digits, mod)
}

func pow10(n int) int {
	r := 1
	for range n {
		r *= 10
	}
	return r
}

// timeStep returns the RFC 6238 counter (T) for an instant.
func timeStep(at time.Time, period time.Duration) int64 {
	return at.Unix() / int64(period.Seconds())
}

// validateTOTP reports whether code matches the TOTP for the secret at instant `at`, scanning
// ±skew periods for clock drift. On a match it returns the accepted step counter. Codes are
// compared in constant time.
func validateTOTP(secret, code string, at time.Time, digits int, period time.Duration, skew int) (int64, bool) {
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, false
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return 0, false
	}

	step := timeStep(at, period)
	for i := -skew; i <= skew; i++ {
		c := step + int64(i)
		if c < 0 {
			continue
		}
		candidate := hotp(key, uint64(c), digits)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}
