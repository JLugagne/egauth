package codesvc_test

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/internal/codesvc"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/ceremony"
)

func TestCodeRequestSendsNothingWhenTheBindCannotBeSet(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	codesvc.BreakBindCookie(w.svc)
	rec := w.do(req{path: routes.CodeRequest, fields: map[string]string{routes.FieldIdentifier: "ann@example.com"}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code request without a bind = %d %s; want 500", rec.Code, rec.Body.String())
	}
	w.flush()
	if msgs := w.mail.all(); len(msgs) != 0 {
		t.Fatalf("a code was delivered for a ceremony the client can never complete: %+v", msgs)
	}
}

func TestMagicLinkRequestSendsNothingWhenTheBindCannotBeSet(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	codesvc.BreakBindCookie(w.svc)
	rec := w.do(req{path: routes.MagicLinkRequest, fields: map[string]string{routes.FieldIdentifier: "ann@example.com"}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("link request without a bind = %d %s; want 500", rec.Code, rec.Body.String())
	}
	w.flush()
	if msgs := w.mail.all(); len(msgs) != 0 {
		t.Fatalf("a link was delivered for a ceremony the client can never complete: %+v", msgs)
	}
}

type tracingStore struct {
	ceremony.Store
	mu    sync.Mutex
	calls []string
}

func (s *tracingStore) note(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, name)
}

func (s *tracingStore) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.calls
	s.calls = nil
	return out
}

func (s *tracingStore) Peek(ctx context.Context, t core.TenantID, k ceremony.Kind, h []byte) (ceremony.Record, error) {
	s.note("Peek")
	return s.Store.Peek(ctx, t, k, h)
}

func (s *tracingStore) Consume(ctx context.Context, t core.TenantID, k ceremony.Kind, h []byte) (ceremony.Record, error) {
	s.note("Consume")
	return s.Store.Consume(ctx, t, k, h)
}

func (s *tracingStore) RecordFailure(ctx context.Context, t core.TenantID, k ceremony.Kind, h []byte) (int, error) {
	s.note("RecordFailure")
	return s.Store.RecordFailure(ctx, t, k, h)
}

func TestWrongCodeCostsTheSameStoreWorkForARealAndADecoyHandle(t *testing.T) {
	w := newWorld(t)
	trace := &tracingStore{Store: w.ceremonies}
	w.ceremonies = trace
	w.build()
	w.user("ann@example.com")
	real := w.requestCode("ann@example.com", w.mail)
	decoyRec := w.do(req{path: routes.CodeRequest, fields: map[string]string{routes.FieldIdentifier: "nobody@example.com"}})
	w.flush()
	decoy := issuedCode{handle: decode(t, decoyRec)["handle"], bind: bindCookie(decoyRec)}
	wrong := otherCode(real.code)
	cases := []struct {
		name string
		do   func(issuedCode) map[string]string
	}{
		{"bound", func(c issuedCode) map[string]string { return w.verify(c, wrong) }},
		{"unbound", func(c issuedCode) map[string]string {
			rec := w.do(req{path: routes.CodeVerify, fields: map[string]string{routes.FieldHandle: c.handle, routes.FieldCode: wrong}})
			m := decode(t, rec)
			m["status"] = http.StatusText(rec.Code)
			return m
		}},
	}
	for _, tc := range cases {
		trace.take()
		a := tc.do(real)
		realCalls := trace.take()
		b := tc.do(decoy)
		decoyCalls := trace.take()
		if a["status"] != b["status"] || a["error"] != b["error"] {
			t.Fatalf("%s: real %v, decoy %v", tc.name, a, b)
		}
		if !slices.Equal(realCalls, decoyCalls) {
			t.Fatalf("%s: a wrong code on a real handle does store work %v, on a decoy %v; the requester can time which accounts exist",
				tc.name, realCalls, decoyCalls)
		}
	}
}
