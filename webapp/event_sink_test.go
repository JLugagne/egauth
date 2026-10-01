package webapp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/webapp"
)

// eventRecordingSink records the security events the preset publishes so a test can assert that
// Config.EventSink receives what the documentation promises.
type eventRecordingSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (s *eventRecordingSink) EmitEvent(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *eventRecordingSink) types() []event.Type {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]event.Type, 0, len(s.events))
	for _, e := range s.events {
		out = append(out, e.Type)
	}
	return out
}

// sinkTestWebApp builds the preset with the given sink and a fresh in-memory identity/token
// stack. It reuses baseConfig() so every webapp test exercises the same configuration path.
func sinkTestWebApp(t *testing.T, sink event.Sink) http.Handler {
	t.Helper()
	cfg := baseConfig()
	cfg.TrustedOrigins = []string{"127.0.0.1"}
	cfg.EventSink = sink
	h, err := webapp.NewWebApp(cfg)
	require.NoError(t, err)
	return h
}

func sinkTestPost(t *testing.T, srv *httptest.Server, path string, form url.Values, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", srv.URL)
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func sinkTestRegister(t *testing.T, srv *httptest.Server) []*http.Cookie {
	t.Helper()
	form := url.Values{"email": {"audit@example.com"}, "password": {"Correct horse battery staple 1!"}}
	resp := sinkTestPost(t, srv, "/auth/register", form, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	return resp.Cookies()
}

// TestNewWebApp_LogoutEventReachesConfiguredSink is the F-INFRA-001 regression test: the preset
// documents Config.EventSink as receiving logout events, but NewWebApp built the tokens handler
// options without tokens.WithEventSink, so LogoutHandler emitted event.Logout into a nil sink and
// the sign-out was silently dropped.
func TestNewWebApp_LogoutEventReachesConfiguredSink(t *testing.T) {
	sink := &eventRecordingSink{}
	srv := httptest.NewServer(sinkTestWebApp(t, sink))
	defer srv.Close()

	cookies := sinkTestRegister(t, srv)
	resp := sinkTestPost(t, srv, "/auth/logout", url.Values{}, cookies)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "logout must succeed")

	assert.Contains(t, sink.types(), event.Logout,
		"Config.EventSink documents logout events; the preset must wire the sink into the tokens handlers")
}

// TestNewWebApp_RefreshReuseEventReachesConfiguredSink is the control proving the sink is live:
// the issuer webapp builds already carries the same sink, so refresh-token reuse is reported.
func TestNewWebApp_RefreshReuseEventReachesConfiguredSink(t *testing.T) {
	sink := &eventRecordingSink{}
	srv := httptest.NewServer(sinkTestWebApp(t, sink))
	defer srv.Close()

	cookies := sinkTestRegister(t, srv)
	first := sinkTestPost(t, srv, "/auth/refresh", url.Values{}, cookies)
	_ = first.Body.Close()
	require.Equal(t, http.StatusNoContent, first.StatusCode)

	replay := sinkTestPost(t, srv, "/auth/refresh", url.Values{}, cookies)
	_ = replay.Body.Close()

	assert.Contains(t, sink.types(), event.RefreshReuseDetected,
		"the issuer already wires the sink; this control pins that the sink is live")
}
