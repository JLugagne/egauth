package webapp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/webapp"
	"github.com/stretchr/testify/require"
)

// capturingSink is a thread-safe event.Sink that records every emitted event, used to prove
// which handler families actually forward to Config.EventSink.
type capturingSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (s *capturingSink) EmitEvent(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *capturingSink) has(typ event.Type) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if e.Type == typ {
			return true
		}
	}
	return false
}

// TestPreset_LogoutEmitsEventOnConfiguredSink proves that Config.EventSink — documented as
// receiving "login, registration and logout events" — actually receives the logout event
// LogoutHandler emits. The preset wires the sink into the identity handlers (login/registration)
// and the refresh-rotation issuer, but must ALSO wire it into the tokens handler options so
// LogoutHandler's own event.Logout emission (Reason="token_logout") reaches the configured sink
// instead of being silently dropped by a handler-local nil sink.
func TestPreset_LogoutEmitsEventOnConfiguredSink(t *testing.T) {
	sink := &capturingSink{}
	cfg := baseConfig()
	cfg.InsecureNoOriginCheck = true
	cfg.EventSink = sink

	h, err := webapp.NewWebApp(cfg)
	require.NoError(t, err)

	regResp := postForm(t, h, "/auth/register", url.Values{
		"email":    {"eventsink@example.com"},
		"password": {"Correct horse battery staple 1!"},
	})
	require.Equal(t, http.StatusNoContent, regResp.StatusCode)

	var rc *http.Cookie
	name := tokens.DefaultCookies().RefreshName
	for _, c := range regResp.Cookies() {
		if c.Name == name && c.Value != "" {
			rc = c
		}
	}
	require.NotNil(t, rc, "registration must issue a refresh cookie")

	logoutResp := postForm(t, h, "/auth/logout", url.Values{}, rc)
	require.Equal(t, http.StatusNoContent, logoutResp.StatusCode)

	require.True(t, sink.has(event.Logout),
		"Config.EventSink must receive the event.Logout emitted by LogoutHandler; "+
			"the preset's tokens handler options never wired the configured sink")
}

func postForm(t *testing.T, h http.Handler, path string, form url.Values, cookies ...*http.Cookie) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}
