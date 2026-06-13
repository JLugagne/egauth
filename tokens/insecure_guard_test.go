package tokens_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureSink records every emitted event for assertions.
type captureSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *captureSink) EmitEvent(_ context.Context, e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureSink) ofType(t event.Type) []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []event.Event
	for _, e := range c.events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// okRotator always rotates successfully so the handler reaches the cookie-writing path.
func okRotator() *issuertest.MockRotator[struct{}] {
	return &issuertest.MockRotator[struct{}]{
		RotateFunc: func(ctx context.Context, tenantID, refreshToken string) (*tokens.TokenPair[struct{}], error) {
			return &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r"}, nil
		},
	}
}

func serveRefresh(h http.HandlerFunc, host string, tlsOn bool) {
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: tokens.DefaultRefreshCookieName, Value: "some-refresh"})
	req.Host = host
	if tlsOn {
		req.TLS = &tls.ConnectionState{}
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
}

// TestInsecureCookies_NonLoopbackEmitsWarning is the repro: Insecure cookies served to a
// non-loopback host must surface a security-event warning. Before the guard exists this
// emits nothing.
func TestInsecureCookies_NonLoopbackEmitsWarning(t *testing.T) {
	sink := &captureSink{}
	h := tokens.RefreshHandler[struct{}](okRotator(),
		tokens.WithInsecureCookies(),
		tokens.WithHandlerEventSink(sink),
	)

	serveRefresh(h, "app.example.com", false)

	warns := sink.ofType(event.InsecureCookieMisuse)
	require.Len(t, warns, 1, "expected exactly one insecure-cookie misuse warning")
	assert.Equal(t, "app.example.com", warns[0].Attrs["host"])
}

// TestInsecureCookies_WarningFiresOnce ensures the warning is rate-limited to once per
// handler, not emitted per request.
func TestInsecureCookies_WarningFiresOnce(t *testing.T) {
	sink := &captureSink{}
	h := tokens.RefreshHandler[struct{}](okRotator(),
		tokens.WithInsecureCookies(),
		tokens.WithHandlerEventSink(sink),
	)

	serveRefresh(h, "app.example.com", false)
	serveRefresh(h, "app.example.com", false)
	serveRefresh(h, "app.example.com", false)

	assert.Len(t, sink.ofType(event.InsecureCookieMisuse), 1)
}

// TestInsecureCookies_LoopbackEmitsNothing guards against false positives on local dev hosts.
func TestInsecureCookies_LoopbackEmitsNothing(t *testing.T) {
	for _, host := range []string{"localhost", "localhost:8080", "127.0.0.1", "127.0.0.1:8080", "[::1]", "[::1]:8080"} {
		t.Run(host, func(t *testing.T) {
			sink := &captureSink{}
			h := tokens.RefreshHandler[struct{}](okRotator(),
				tokens.WithInsecureCookies(),
				tokens.WithHandlerEventSink(sink),
			)
			serveRefresh(h, host, false)
			assert.Empty(t, sink.ofType(event.InsecureCookieMisuse))
		})
	}
}

// TestInsecureCookies_SecureNeverWarns ensures secure cookies (the default) never warn,
// even on a non-loopback host.
func TestInsecureCookies_SecureNeverWarns(t *testing.T) {
	sink := &captureSink{}
	h := tokens.RefreshHandler[struct{}](okRotator(),
		tokens.WithHandlerEventSink(sink),
	)

	serveRefresh(h, "app.example.com", false)

	assert.Empty(t, sink.ofType(event.InsecureCookieMisuse))
}

// TestInsecureCookies_TLSTerminatedEmitsNothing ensures a TLS request does not warn even
// when Insecure is set on a non-loopback host (the connection is in fact encrypted).
func TestInsecureCookies_TLSTerminatedEmitsNothing(t *testing.T) {
	sink := &captureSink{}
	h := tokens.RefreshHandler[struct{}](okRotator(),
		tokens.WithInsecureCookies(),
		tokens.WithHandlerEventSink(sink),
	)

	serveRefresh(h, "app.example.com", true)

	assert.Empty(t, sink.ofType(event.InsecureCookieMisuse))
}

// TestInsecureCookies_LogoutHandlerWarns ensures the guard also covers the logout handler.
func TestInsecureCookies_LogoutHandlerWarns(t *testing.T) {
	sink := &captureSink{}
	revoker := memory.NewStore[struct{}]()
	h := tokens.LogoutHandler(revoker,
		tokens.WithInsecureCookies(),
		tokens.WithHandlerEventSink(sink),
	)

	serveRefresh(h, "app.example.com", false)

	assert.Len(t, sink.ofType(event.InsecureCookieMisuse), 1)
}
