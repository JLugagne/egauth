package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/session"
)

// EndpointFunc is the body of an auth endpoint. It receives only a Request built by the
// preamble: capped, parsed once, and past every gate its Meta requires.
type EndpointFunc func(w http.ResponseWriter, r *Request)

// Request is one auth request after the preamble. Its fields come from the body for unsafe
// methods and from the URL query for safe ones, restricted to the closed Field* set; any other
// field is dropped and never echoed. It renders without field values under fmt and slog, as a
// pointer or as a value.
type Request struct {
	http      *http.Request
	endpoint  string
	meta      Meta
	tenant    core.TenantID
	client    clientaddr.Client
	fields    map[string]string
	jsonBody  bool
	raw       []byte
	resumed   session.Resumed
	hasSess   bool
	transport core.Transport
}

// HTTP returns the underlying request for path values, headers, internal/cookie reads and
// Backend.End. Its body has been replaced by an empty one (read for unsafe methods, discarded
// unread for safe ones); reparsing it yields nothing.
func (r *Request) HTTP() *http.Request { return r.http }

func (r *Request) Context() context.Context { return r.http.Context() }

// Endpoint returns the endpoint path relative to BasePath.
func (r *Request) Endpoint() string { return r.endpoint }

func (r *Request) Meta() Meta { return r.meta }

// Tenant returns the tenant resolved by the preamble.
func (r *Request) Tenant() core.TenantID { return r.tenant }

// Client returns the client resolved under the proxy policy.
func (r *Request) Client() clientaddr.Client { return r.client }

// Field returns the value of a Field* name, or "" when absent or when name is not in the set.
func (r *Request) Field(name string) string { return r.fields[name] }

// Has reports whether the Field* name was sent, even empty.
func (r *Request) Has(name string) bool {
	_, ok := r.fields[name]
	return ok
}

// Flag reports whether the Field* name holds a true value: "true", "1", "on" or "yes", any case.
func (r *Request) Flag(name string) bool {
	switch strings.ToLower(r.fields[name]) {
	case "true", "1", "on", "yes":
		return true
	}
	return false
}

// Session returns the resumed session, and false unless Meta.Authenticated.
func (r *Request) Session() (session.Resumed, bool) { return r.resumed, r.hasSess }

// Transport returns the session's sealed transport when a session was resumed. Otherwise it is
// the transport a new journey would seal: Bearer only when the deployment allows Bearer and either
// allows nothing else, X-Egauth-Transport is "bearer", or the endpoint has Meta.EndsSession and the
// cookieless request carries an Authorization Bearer credential; Cookies in every other case.
func (r *Request) Transport() core.Transport { return r.transport }

// WebAuthnBody returns a copy of the raw JSON body of an endpoint with the WebAuthn body cap, for
// the WebAuthn parser; nil for every other endpoint.
func (r *Request) WebAuthnBody() []byte { return slices.Clone(r.raw) }

func (r Request) String() string {
	return "httpx.Request{" + r.endpoint + " tenant=" + r.tenant.String() + "}"
}

func (r Request) GoString() string { return r.String() }

func (r Request) LogValue() slog.Value {
	return slog.GroupValue(slog.String("endpoint", r.endpoint), slog.String("tenant", r.tenant.String()))
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func parse(hr *http.Request, meta Meta) (map[string]string, bool, []byte, error) {
	if safeMethod(hr.Method) {
		_ = hr.Body.Close()
		hr.Body = http.NoBody
		f, err := fromValues(hr.URL.Query())
		return f, false, nil, err
	}
	body, err := io.ReadAll(hr.Body)
	_ = hr.Body.Close()
	hr.Body = http.NoBody
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, false, nil, ErrBodyTooLarge
		}
		return nil, false, nil, errors.Join(ErrInvalidRequest, err)
	}
	ct := hr.Header.Get("Content-Type")
	if ct == "" && len(body) == 0 {
		return map[string]string{}, false, nil, nil
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return nil, false, nil, ErrUnsupportedMedia
	}
	switch mt {
	case "application/json":
		f, err := fromJSON(body)
		if err != nil {
			return nil, false, nil, err
		}
		var raw []byte
		if meta.BodyCap == WebAuthnBodyCap {
			raw = body
		}
		return f, true, raw, nil
	case "application/x-www-form-urlencoded":
		vs, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, false, nil, errors.Join(ErrInvalidRequest, err)
		}
		f, err := fromValues(vs)
		return f, false, nil, err
	}
	return nil, false, nil, ErrUnsupportedMedia
}

func fromValues(vs url.Values) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range vs {
		if !isField(k) {
			continue
		}
		if len(v) != 1 {
			return nil, errors.Join(ErrInvalidRequest, errors.New("repeated field "+k))
		}
		out[k] = v[0]
	}
	return out, nil
}

func fromJSON(body []byte) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.Join(ErrInvalidRequest, errors.New("body is not a JSON object"))
	}
	out := map[string]string{}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errors.Join(ErrInvalidRequest, err)
		}
		key, _ := tok.(string)
		if seen[key] {
			return nil, errors.Join(ErrInvalidRequest, errors.New("repeated key"))
		}
		seen[key] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, errors.Join(ErrInvalidRequest, err)
		}
		if !isField(key) {
			continue
		}
		v, present, err := scalar(raw)
		if err != nil {
			return nil, err
		}
		if present {
			out[key] = v
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errors.Join(ErrInvalidRequest, errors.New("unterminated object"))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.Join(ErrInvalidRequest, errors.New("trailing data"))
	}
	return out, nil
}

func scalar(raw json.RawMessage) (string, bool, error) {
	switch t := bytes.TrimSpace(raw); {
	case len(t) == 0:
		return "", false, ErrInvalidRequest
	case t[0] == '"':
		var s string
		if err := json.Unmarshal(t, &s); err != nil {
			return "", false, errors.Join(ErrInvalidRequest, err)
		}
		return s, true, nil
	case bytes.Equal(t, []byte("null")):
		return "", false, nil
	case bytes.Equal(t, []byte("true")), bytes.Equal(t, []byte("false")):
		return string(t), true, nil
	case t[0] == '-' || (t[0] >= '0' && t[0] <= '9'):
		return string(t), true, nil
	}
	return "", false, errors.Join(ErrInvalidRequest, errors.New("field is not a scalar"))
}
