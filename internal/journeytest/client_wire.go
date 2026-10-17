package journeytest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/csrf"
)

// HeaderValue is one request header of the set a browser attaches to a cross-site request. The
// names come from internal/csrf, the only owner of the Origin, Referer and Sec-Fetch-* literals.
type HeaderValue struct {
	Name  string
	Value string
}

func Origin(value string) HeaderValue {
	return HeaderValue{Name: csrf.HeaderOrigin, Value: value}
}

func Referer(value string) HeaderValue {
	return HeaderValue{Name: csrf.HeaderReferer, Value: value}
}

func FetchSite(value string) HeaderValue {
	return HeaderValue{Name: csrf.HeaderFetchSite, Value: value}
}

func FetchMode(value string) HeaderValue {
	return HeaderValue{Name: csrf.HeaderFetchMode, Value: value}
}

// Headers returns the headers h as an http.Header.
func Headers(h ...HeaderValue) http.Header {
	out := http.Header{}
	for _, v := range h {
		out.Add(v.Name, v.Value)
	}
	return out
}

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }

type memListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *memListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80} }

const shutdownBound = 30 * time.Second

type memServer struct {
	l  *memListener
	hc *http.Client
}

func newMemServer(t testing.TB, h http.Handler) *memServer {
	l := &memListener{conns: make(chan net.Conn), done: make(chan struct{})}
	srv := httptest.NewUnstartedServer(h)
	_ = srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(func() {
		srv.CloseClientConnections()
		done := make(chan struct{})
		go func() {
			srv.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(shutdownBound):
			t.Errorf("journeytest: the in-memory server did not shut down within %s: a handler is blocked", shutdownBound)
		}
	})
	m := &memServer{l: l, hc: srv.Client()}
	tr, _ := m.hc.Transport.(*http.Transport)
	tr.DisableKeepAlives = true
	tr.DisableCompression = true
	tr.DialContext = m.dial
	m.hc.Timeout = 60 * time.Second
	m.hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return m
}

func (m *memServer) dial(ctx context.Context, _, remote string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	select {
	case m.l.conns <- remoteConn{Conn: server, remote: net.TCPAddrFromAddrPort(ap)}:
		return client, nil
	case <-m.l.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
