package httpx

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/JLugagne/egauth/internal/core"
)

const (
	tenantMarker   = "{tenant}"
	maxTenantLabel = 63
)

var (
	// ErrNoTenant is returned by a resolver that cannot name the tenant of a request.
	ErrNoTenant = errors.New("httpx: tenant not resolved")
	// ErrInvalidTenancy is returned by TenantBySubdomain for an origin without a leading {tenant}
	// host label.
	ErrInvalidTenancy = errors.New("httpx: invalid tenancy")
)

type singleTenant struct{}

func (singleTenant) ResolveTenant(*http.Request) (core.TenantID, error) {
	return core.TenantID{}, nil
}

// SingleTenant resolves every request to the zero TenantID. It is the only resolver whose zero
// answer the preamble accepts.
func SingleTenant() TenantResolver { return singleTenant{} }

type subdomainTenant struct {
	suffix string
	port   string
	scheme string
}

// TenantBySubdomain resolves the tenant from the first host label of the request, matched against
// publicOrigin of the form scheme://{tenant}.parent[:port]. The label must match [a-z0-9-]{1,63}
// and the port must be the origin's. It returns ErrInvalidTenancy for any other origin.
func TenantBySubdomain(publicOrigin string) (TenantResolver, error) {
	scheme, rest, ok := strings.Cut(publicOrigin, "://")
	if !ok || !strings.HasPrefix(rest, tenantMarker+".") || strings.Count(publicOrigin, tenantMarker) != 1 {
		return nil, errors.Join(ErrInvalidTenancy, errors.New("origin needs a leading {tenant} label"))
	}
	u, err := url.Parse(scheme + "://t" + strings.TrimPrefix(rest, tenantMarker))
	if err != nil || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.Join(ErrInvalidTenancy, errors.New("not an origin"))
	}
	s := strings.ToLower(u.Scheme)
	if s != "https" && s != "http" {
		return nil, errors.Join(ErrInvalidTenancy, errors.New("origin scheme"))
	}
	return subdomainTenant{suffix: strings.ToLower(strings.TrimPrefix(u.Hostname(), "t")), port: u.Port(), scheme: s}, nil
}

func (s subdomainTenant) ResolveTenant(r *http.Request) (core.TenantID, error) {
	host, port := r.Host, ""
	if h, p, err := net.SplitHostPort(r.Host); err == nil {
		host, port = h, p
	}
	if !s.portMatches(port) {
		return core.TenantID{}, errors.Join(ErrNoTenant, errors.New("port"))
	}
	label, ok := strings.CutSuffix(strings.ToLower(host), s.suffix)
	if !ok || !validLabel(label) {
		return core.TenantID{}, errors.Join(ErrNoTenant, errors.New("host"))
	}
	return core.ParseTenantID(label)
}

func (s subdomainTenant) portMatches(port string) bool {
	if port == s.port {
		return true
	}
	def := map[string]string{"https": "443", "http": "80"}[s.scheme]
	return (port == "" && s.port == def) || (s.port == "" && port == def)
}

func validLabel(l string) bool {
	if l == "" || len(l) > maxTenantLabel {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}
