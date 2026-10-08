package clientaddr_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clientaddr"
)

type recordingSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (s *recordingSink) EmitEvent(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *recordingSink) count(t event.Type) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e.Type == t {
			n++
		}
	}
	return n
}

func request(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func resolver(t *testing.T, p clientaddr.Policy, sink event.Sink) *clientaddr.Resolver {
	t.Helper()
	r, err := clientaddr.New(p, sink)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTrustedRejectsBroadPrefixes(t *testing.T) {
	for _, s := range []string{"0.0.0.0/0", "10.0.0.0/7", "::/0", "2001::/15", "::ffff:10.0.0.0/100"} {
		if _, err := clientaddr.Trusted(mustPrefix(t, s)); !errors.Is(err, clientaddr.ErrPrefixTooBroad) {
			t.Errorf("%s: want ErrPrefixTooBroad, got %v", s, err)
		}
	}
	if _, err := clientaddr.Trusted(mustPrefix(t, "10.0.0.0/8"), netip.Prefix{}); !errors.Is(err, clientaddr.ErrInvalidPolicy) {
		t.Errorf("invalid prefix: want ErrInvalidPolicy, got %v", err)
	}
	for _, s := range []string{"10.0.0.0/8", "2001:db8::/16", "192.0.2.10/32"} {
		if _, err := clientaddr.Trusted(mustPrefix(t, s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
}

func TestZeroPolicyIsRefused(t *testing.T) {
	if _, err := clientaddr.New(clientaddr.Policy{}, nil); !errors.Is(err, clientaddr.ErrInvalidPolicy) {
		t.Fatalf("want ErrInvalidPolicy, got %v", err)
	}
}

func TestDirectUsesPeerOnly(t *testing.T) {
	sink := &recordingSink{}
	res := resolver(t, clientaddr.Direct(), sink)
	c, err := res.Resolve(request("203.0.113.7:4000", "198.51.100.1"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr() != netip.MustParseAddr("203.0.113.7") || c.Key() != "203.0.113.7" {
		t.Fatalf("got %v %q", c.Addr(), c.Key())
	}
	if sink.count(event.ProxyHeadersIgnored) != 0 {
		t.Fatal("public peer must not emit ProxyHeadersIgnored")
	}
}

func TestDirectEmitsProxyHeadersIgnoredOnceForPrivatePeer(t *testing.T) {
	sink := &recordingSink{}
	res := resolver(t, clientaddr.Direct(), sink)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			c, err := res.Resolve(request("10.1.2.3:4000", "198.51.100.1"))
			if err != nil || c.Key() != "10.1.2.3" {
				t.Errorf("got %v %v", c.Key(), err)
			}
		})
	}
	wg.Wait()
	if _, err := res.Resolve(request("127.0.0.1:1", "198.51.100.1")); err != nil {
		t.Fatal(err)
	}
	if n := sink.count(event.ProxyHeadersIgnored); n != 1 {
		t.Fatalf("want exactly one ProxyHeadersIgnored, got %d", n)
	}
}

func TestDirectPrivatePeerWithoutHeaderEmitsNothing(t *testing.T) {
	sink := &recordingSink{}
	res := resolver(t, clientaddr.Direct(), sink)
	if _, err := res.Resolve(request("10.1.2.3:4000")); err != nil {
		t.Fatal(err)
	}
	if sink.count(event.ProxyHeadersIgnored) != 0 {
		t.Fatal("no forwarding header, no event")
	}
}

func TestTrustedWalksForwardedForFromTheRight(t *testing.T) {
	p, err := clientaddr.Trusted(mustPrefix(t, "10.0.0.0/8"), mustPrefix(t, "192.168.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	res := resolver(t, p, nil)
	cases := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"untrusted peer ignores header", "203.0.113.9:1", []string{"198.51.100.1"}, "203.0.113.9"},
		{"trusted peer, no header", "10.0.0.1:1", nil, "10.0.0.1"},
		{"single hop", "10.0.0.1:1", []string{"198.51.100.1"}, "198.51.100.1"},
		{"spoofed left entries are skipped", "10.0.0.1:1", []string{"1.1.1.1, 198.51.100.1"}, "198.51.100.1"},
		{"trusted chain is skipped", "10.0.0.1:1", []string{"6.6.6.6, 198.51.100.1, 192.168.1.1, 10.2.2.2"}, "198.51.100.1"},
		{"multiple header lines are one list", "10.0.0.1:1", []string{"6.6.6.6", "198.51.100.1, 10.2.2.2"}, "198.51.100.1"},
		{"all trusted gives leftmost", "10.0.0.1:1", []string{"10.9.9.9, 192.168.3.3"}, "10.9.9.9"},
		{"garbage stops at the proxy that wrote it", "10.0.0.1:1", []string{"198.51.100.1, garbage, 10.2.2.2"}, "10.2.2.2"},
		{"garbage at the edge gives peer", "10.0.0.1:1", []string{"garbage"}, "10.0.0.1"},
		{"port in entry", "10.0.0.1:1", []string{"198.51.100.1:5555"}, "198.51.100.1"},
		{"mapped v4 is unmapped", "[::ffff:10.0.0.1]:1", []string{"::ffff:198.51.100.1"}, "198.51.100.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := res.Resolve(request(tc.remote, tc.xff...))
			if err != nil {
				t.Fatal(err)
			}
			if c.Addr().String() != tc.want {
				t.Fatalf("got %s want %s", c.Addr(), tc.want)
			}
		})
	}
}

func TestOtherForwardingHeadersAreNeverTrusted(t *testing.T) {
	p, err := clientaddr.Trusted(mustPrefix(t, "10.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}
	r := request("10.0.0.1:1")
	r.Header.Set("Forwarded", "for=198.51.100.1")
	r.Header.Set("X-Real-Ip", "198.51.100.2")
	c, err := resolver(t, p, nil).Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr().String() != "10.0.0.1" {
		t.Fatalf("got %s", c.Addr())
	}
}

func TestKeyIsAddressForIPv4AndSlash64ForIPv6(t *testing.T) {
	res := resolver(t, clientaddr.Direct(), nil)
	a, err := res.Resolve(request("[2001:db8:1:2:aaaa::1]:443"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := res.Resolve(request("[2001:db8:1:2:bbbb::9]:443"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Key() != "2001:db8:1:2::/64" || a.Key() != b.Key() {
		t.Fatalf("v6 keys %q %q", a.Key(), b.Key())
	}
	c, err := res.Resolve(request("[fe80::1%eth0]:443"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Key() != "fe80::/64" {
		t.Fatalf("zoned key %q", c.Key())
	}
}

func TestUnparsableRemoteAddrFailsClosed(t *testing.T) {
	res := resolver(t, clientaddr.Direct(), nil)
	for _, remote := range []string{"", "@", "not-an-ip:1"} {
		if _, err := res.Resolve(request(remote)); !errors.Is(err, clientaddr.ErrNoClient) {
			t.Errorf("%q: want ErrNoClient, got %v", remote, err)
		}
	}
	c, err := res.Resolve(request("198.51.100.4"))
	if err != nil || c.Key() != "198.51.100.4" {
		t.Fatalf("bare address: %v %v", c.Key(), err)
	}
}
