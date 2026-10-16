package hibp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
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
