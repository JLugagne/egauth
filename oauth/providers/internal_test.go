package providers

import (
	"context"
	"errors"
	"testing"

	"github.com/JLugagne/egauth/oauth"
)

// TestFetchAppleUser_FailsClosed documents that Apple exposes no userinfo endpoint: the fetch
// func reached only when Apple is configured WITHOUT oauth.WithOIDC must fail closed with a
// wrapped ErrUserInfoFailed instead of issuing a doomed HTTP request.
func TestFetchAppleUser_FailsClosed(t *testing.T) {
	_, err := fetchAppleUser(context.Background(), nil, "access-token")
	if err == nil {
		t.Fatal("expected an error: Apple has no userinfo endpoint")
	}
	if !errors.Is(err, oauth.ErrUserInfoFailed) {
		t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
	}
}

func TestStringifyID(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"string", "abc123", "abc123"},
		{"json number", float64(42), "42"},
		{"large json number", float64(9007199254740992), "9007199254740992"},
		{"nil", nil, ""},
		{"unexpected type", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stringifyID(tc.in); got != tc.want {
				t.Errorf("stringifyID(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
