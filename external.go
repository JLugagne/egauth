package egauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/JLugagne/egauth/principal"
)

// ExternalFactor is a primary factor verified by the application, for LDAP, SAML bridges or an
// internal SSO. POST {BasePath}/external/{Name}/login calls Verify; a success maps ExternalID to an
// account through the federation store, never auto-links, and still goes through the MFA policy
// and the account state. Name must be a token (1 to 32 of [a-z0-9_-]) unique among the factors.
// Implementations must be safe for concurrent use and must not log ExternalRequest.Secret.
type ExternalFactor interface {
	Name() string
	Verify(ctx context.Context, req ExternalRequest) (ExternalIdentity, error)
}

// ExternalRequest carries no request body beyond the fixed identifier and secret fields. fmt, slog
// and encoding/json render Secret as REDACTED.
type ExternalRequest struct {
	Tenant     principal.TenantID
	Identifier string
	Secret     string
}

// String renders r with Secret redacted.
func (r ExternalRequest) String() string {
	return fmt.Sprintf("ExternalRequest{Tenant:%s Identifier:%s Secret:%s}", r.Tenant, r.Identifier, redactedSecret)
}

// GoString renders r for %#v with Secret redacted.
func (r ExternalRequest) GoString() string { return r.String() }

// Format renders r like String for every fmt verb, so no verb reaches Secret.
func (r ExternalRequest) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.String()) }

// MarshalJSON encodes r with Secret redacted.
func (r ExternalRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Tenant     string `json:"tenant"`
		Identifier string `json:"identifier"`
		Secret     string `json:"secret"`
	}{r.Tenant.String(), r.Identifier, redactedSecret})
}

// LogValue renders r for slog with Secret redacted.
func (r ExternalRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("tenant", r.Tenant.String()),
		slog.String("identifier", r.Identifier),
		slog.String("secret", redactedSecret),
	)
}

// ExternalIdentity is the account an ExternalFactor vouches for. ExternalID is stable for the
// account at the source; Email is adopted as verified only when EmailVerified is true.
type ExternalIdentity struct {
	ExternalID    string
	Email         string
	EmailVerified bool
}
