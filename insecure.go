package egauth

import (
	"net/netip"
	"strings"
)

// InsecureOptOuts is the only place where a default control is weakened. Every set field must carry
// an acknowledgement with a non-empty reason, otherwise New fails; each is listed by Auth.Posture.
type InsecureOptOuts struct {
	// NoOriginCheck disables the CSRF and fetch-metadata gate.
	NoOriginCheck *Ack
	// NoRateLimit disables the library rate limits and the limiter probe of New.
	NoRateLimit *Ack
	// NoReauthWindow drops the freshness requirement of sensitive actions; MFA still applies.
	NoReauthWindow *Ack
	// LongSessions raises the SessionPolicy.MaxLifetime bound from 90 days to 400 days.
	LongSessions *Ack
	// EphemeralState accepts Ephemeral stores on a public origin that is not loopback.
	EphemeralState *Ack
	// SharedCookieDomain drops the __Host- prefix of session cookies and scopes them to a parent
	// domain.
	SharedCookieDomain *SharedCookieDomain
	// OutboundPrivateNetwork lets statically configured providers reach private prefixes.
	OutboundPrivateNetwork *OutboundAllowance
	// TenantOutboundPrivateNetwork lets providers registered by a tenant reach private prefixes.
	TenantOutboundPrivateNetwork *OutboundAllowance
}

// Ack records why an opt-out is acceptable. Build it with Acknowledge.
type Ack struct {
	reason      string
	development bool
}

// Acknowledge records why an opt-out is acceptable; New rejects an empty or blank reason.
func Acknowledge(reason string) *Ack {
	return &Ack{reason: reason}
}

// Reason returns the acknowledged reason; it is empty for a nil Ack.
func (a *Ack) Reason() string {
	if a == nil {
		return ""
	}
	return a.reason
}

func (a *Ack) valid() bool {
	return a != nil && strings.TrimSpace(a.reason) != ""
}

// SharedCookieDomain scopes session cookies to Domain, which New requires to be a registrable
// domain and a suffix of every origin host.
type SharedCookieDomain struct {
	Domain string
	Ack    *Ack
}

// OutboundAllowance lists private prefixes outbound calls may reach. Link-local (169.254.0.0/16,
// fe80::/10), the IPv4 and IPv6 metadata addresses, loopback outside tests, and any prefix shorter
// than /8 (IPv4) or /32 (IPv6) are rejected by New.
type OutboundAllowance struct {
	Prefixes []netip.Prefix
	Ack      *Ack
}
