package hibp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/passwords/breach/hibp"
)

func TestMalformedCountKeepsItsCause(t *testing.T) {
	const pw = "a-passphrase-with-a-malformed-count"
	_, suffix := sha1Hex(pw)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(suffix + ":lots\r\n"))
	}))
	t.Cleanup(srv.Close)
	c := hibp.NewWithHTTPClient(hibp.Config{BaseURL: srv.URL}, srv.Client())
	if _, err := c.IsBreached(context.Background(), pw); !errors.Is(err, strconv.ErrSyntax) {
		t.Fatalf("IsBreached = %v, want an error wrapping strconv.ErrSyntax", err)
	}
}

func TestFailuresWrapDeclaredSentinels(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   error
	}{
		"status":   {status: http.StatusTeapot, want: hibp.ErrUnexpectedStatus},
		"too long": {status: http.StatusOK, body: strings.Repeat("A", 4<<20+1), want: hibp.ErrResponseTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			c := hibp.NewWithHTTPClient(hibp.Config{BaseURL: srv.URL}, srv.Client())
			if _, err := c.IsBreached(context.Background(), "pw"); !errors.Is(err, tc.want) {
				t.Fatalf("IsBreached = %v, want %v", err, tc.want)
			}
		})
	}
}
