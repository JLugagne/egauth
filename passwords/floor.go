package passwords

import (
	"errors"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// MinPasswordLength is the library floor on a new password, in Unicode code points, counted both as
// typed and after NFKC normalisation, so neither a compatibility character that NFKC expands nor a
// sequence it composes can pass with fewer real characters. No Policy can lower it.
const MinPasswordLength = 8

const maxRawPasswordLength = 4 * MaxPasswordLength

// ErrPasswordEncoding is returned by Floor for a password that is not valid UTF-8.
var ErrPasswordEncoding = errors.New("passwords: password is not valid UTF-8")

// Canonical returns the NFKC normal form of password, the form egauth hashes and compares, so a
// password typed with full-width or compatibility characters matches its plain form.
func Canonical(password string) string {
	return norm.NFKC.String(password)
}

// Floor applies the library floor that runs before any Policy: valid UTF-8, then at least
// MinPasswordLength code points both as typed and after NFKC normalisation, and at most
// MaxPasswordLength bytes after it, so a Hasher never refuses an accepted password. It returns the
// NFKC form to hash, or ErrPasswordEncoding, ErrPasswordTooShort or ErrPasswordTooLong.
func Floor(password string) (string, error) {
	if len(password) > maxRawPasswordLength {
		return "", ErrPasswordTooLong
	}
	if !utf8.ValidString(password) {
		return "", ErrPasswordEncoding
	}
	c := Canonical(password)
	if len(c) > MaxPasswordLength {
		return "", ErrPasswordTooLong
	}
	if utf8.RuneCountInString(password) < MinPasswordLength || utf8.RuneCountInString(c) < MinPasswordLength {
		return "", ErrPasswordTooShort
	}
	return c, nil
}
