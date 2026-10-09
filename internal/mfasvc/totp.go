package mfasvc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	totpDigits  = 6
	totpModulus = 1_000_000
	totpPeriod  = 30
	totpSkew    = 1
	secretBytes = 20
)

var secretEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func newSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return secretEncoding.EncodeToString(b), nil
}

func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	return secretEncoding.DecodeString(strings.TrimRight(s, "="))
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	s := strconv.FormatUint(uint64(v%totpModulus), 10)
	return strings.Repeat("0", totpDigits-len(s)) + s
}

func wellFormedTOTP(code string) bool {
	if len(code) != totpDigits {
		return false
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

func matchTOTP(key []byte, code string, now time.Time) (int64, bool) {
	step := now.Unix() / totpPeriod
	var matched int64
	found := 0
	for i := -totpSkew; i <= totpSkew; i++ {
		c := step + int64(i)
		if c < 0 {
			continue
		}
		hit := subtle.ConstantTimeCompare([]byte(hotp(key, uint64(c))), []byte(code))
		if hit == 1 && found == 0 {
			matched = c
		}
		found |= hit
	}
	return matched, found == 1
}

func provisioningURI(secret, issuer, account string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", strconv.Itoa(totpDigits))
	v.Set("period", strconv.Itoa(totpPeriod))
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(account) + "?" + v.Encode()
}
