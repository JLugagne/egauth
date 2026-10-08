package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/redirect"
)

// Problem is an error that carries the status and the machine code sent to the client. Its code
// is the only client-visible part of an error; the wrapped detail never leaves the process.
type Problem struct {
	status int
	code   string
}

// NewProblem returns a Problem answered with status and {"error": code}.
func NewProblem(status int, code string) *Problem {
	return &Problem{status: status, code: code}
}

func (p *Problem) Error() string { return "httpx: " + p.code }

func (p *Problem) Status() int { return p.status }

// Code returns the machine code sent as {"error": code}.
func (p *Problem) Code() string { return p.code }

// The problems the preamble answers.
var (
	ErrUnauthenticated      = NewProblem(http.StatusUnauthorized, "unauthenticated")
	ErrBodyTooLarge         = NewProblem(http.StatusRequestEntityTooLarge, "request_too_large")
	ErrUnsupportedMedia     = NewProblem(http.StatusUnsupportedMediaType, "unsupported_media_type")
	ErrInvalidRequest       = NewProblem(http.StatusBadRequest, "invalid_request")
	ErrCrossSite            = NewProblem(http.StatusForbidden, "cross_site_request")
	ErrRateLimited          = NewProblem(http.StatusTooManyRequests, "rate_limited")
	ErrServiceUnavailable   = NewProblem(http.StatusServiceUnavailable, "unavailable")
	ErrPasswordChangeNeeded = NewProblem(http.StatusForbidden, "password_change_required")
	ErrReauthRequired       = NewProblem(http.StatusForbidden, "reauth_required")
	ErrRequestRejected      = NewProblem(http.StatusForbidden, "request_rejected")
	ErrInternal             = NewProblem(http.StatusInternalServerError, "internal_error")
)

// Response is what an endpoint answers. It carries no transport: Respond and RespondPending take
// it from a sealed source, so a header-derived transport can never choose between 303 and JSON.
// With a Location under sealed TransportCookies, a browser form post or GET gets a 303 to it; in
// every other case the client gets JSON with Status (200 when zero) and Body ({} when nil).
type Response struct {
	Status   int
	Body     any
	Location redirect.Target
}

func secureHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

// Respond writes resp under the transport sealed in r's resumed session. Without a resumed
// session it always answers JSON: a journey step answers with RespondPending instead.
func (r *Request) Respond(w http.ResponseWriter, resp Response) {
	t := core.Transport(0)
	if r.hasSess {
		t = r.resumed.Attrs().Transport()
	}
	r.respond(w, t, resp)
}

// RespondPending writes resp under the transport sealed in p, the journey this request advanced;
// the transport r would request from its headers is ignored. A zero p answers JSON.
func (r *Request) RespondPending(w http.ResponseWriter, p core.Pending, resp Response) {
	r.respond(w, p.Transport(), resp)
}

func (r *Request) respond(w http.ResponseWriter, t core.Transport, resp Response) {
	secureHeaders(w)
	if t == core.TransportCookies && !resp.Location.IsZero() && !r.jsonBody {
		w.Header().Set("Location", resp.Location.String())
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	writeJSON(w, status, resp.Body)
}

// Fail answers err: its Problem when it wraps one, 500 internal_error otherwise. The error text is
// never sent.
func (r *Request) Fail(w http.ResponseWriter, err error) {
	writeProblem(w, err)
}

func writeProblem(w http.ResponseWriter, err error) {
	secureHeaders(w)
	p := ErrInternal
	var target *Problem
	if errors.As(err, &target) && target != nil {
		p = target
	}
	writeJSON(w, p.status, map[string]string{"error": p.code})
}

func writeRateLimited(w http.ResponseWriter, retryAfterSeconds int) {
	if retryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	}
	writeProblem(w, ErrRateLimited)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	if body == nil {
		body = struct{}{}
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		status = http.StatusInternalServerError
		buf.Reset()
		buf.WriteString(`{"error":"internal_error"}` + "\n")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
