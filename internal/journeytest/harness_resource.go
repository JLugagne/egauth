package journeytest

import (
	"crypto/x509"
	"errors"
	"net/http"
	"testing"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
)

// ResourceRoute is the one route of a ResourceWorld's resource server.
const ResourceRoute = "/resource/data"

// ResourceWorld is a World served over loopback HTTP with a ResourceServer in front of
// AudienceOne, sharing the Auth's storage for revocation.
type ResourceWorld struct {
	Auth    *World
	Server  *egauth.ResourceServer[Claims]
	Handler http.Handler
	Seen    *Seen
}

// NewResourceWorld builds a single-tenant JWT World on loopback and a ResourceServer for AudienceOne;
// it fails t when either refuses its configuration.
func NewResourceWorld(t testing.TB, s Settings) *ResourceWorld {
	t.Helper()
	rw, err := BuildResourceWorld(t, s)
	if err != nil {
		t.Fatalf("journeytest: building the resource world: %v", err)
	}
	return rw
}

// BuildResourceWorld is NewResourceWorld returning the error the Auth or the ResourceServer reported, so
// that a configuration variant the library rejects can be told from one it accepts. The loopback
// server has no dialer seam for a {tenant} host, so the ResourceServer is only reachable, and only
// probed, under single tenancy.
func BuildResourceWorld(t testing.TB, s Settings) (*ResourceWorld, error) {
	t.Helper()
	s.Backend, s.Serve = JWT, true
	w, err := BuildWorld(t, s)
	if err != nil {
		return nil, err
	}
	srv, err := egauthTestResourceServer(w)
	if err != nil {
		return nil, errors.Join(errors.New("journeytest: building the resource server"), err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	seen := &Seen{}
	h, err := srv.Routes().Protect("GET "+ResourceRoute, seen.handler).Build()
	if err != nil {
		return nil, errors.Join(errors.New("journeytest: building the resource routes"), err)
	}
	return &ResourceWorld{Auth: w, Server: srv, Handler: h, Seen: seen}, nil
}

func egauthTestResourceServer(w *World) (*egauth.ResourceServer[Claims], error) {
	roots := x509.NewCertPool()
	roots.AddCert(w.Server.Certificate())
	return egauthtest.NewResourceServer[Claims](egauth.ResourceConfig{
		AuthOrigin: w.Origin,
		Audience:   AudienceOne,
		Proxy:      egauth.DirectClients(),
		Revocation: egauth.FromStorage(w.Storage),
		Events:     event.Discard,
	}, w.Clock, roots)
}
