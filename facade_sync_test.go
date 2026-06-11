package egauth_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/sessions"
)

// TestSingleTenantFacadeInSync guards the hand-written SingleTenant facades against drift from
// the Service API they shadow. Each of identity/sessions/mfa/otp/passkey exposes a tenant-aware
// Service plus a SingleTenant convenience wrapper that mirrors every Service method minus the
// tenantID argument. The wrappers are hand-maintained, so a newly added Service method can
// silently fail to appear on SingleTenant. This test reflects the exported method set of each
// Service and asserts every method NAME has a matching SingleTenant method.
//
// Comparison is by method NAME only: the signatures legitimately differ (SingleTenant drops the
// tenantID argument), so a full-signature match would never hold. Adding a new exported Service
// method without the corresponding SingleTenant method fails this test (spot-checked).
//
// NOTE: tokens/jwt is intentionally NOT covered here.
func TestSingleTenantFacadeInSync(t *testing.T) {
	cases := []struct {
		// pkg names the module for failure messages.
		pkg string
		// service is the type whose exported methods define the API the facade must mirror.
		// For interface-based Services pass the interface type; for the struct-based passkey
		// Service pass its pointer type (its exported methods are the public API).
		service reflect.Type
		// facade is the SingleTenant pointer type whose method set must cover service.
		facade reflect.Type
		// allow lists Service method names that legitimately need NOT appear on the facade.
		// Keep this tight and documented; today every Service method is mirrored, so all
		// allowlists are empty.
		allow map[string]string
	}{
		{
			pkg:     "identity",
			service: reflect.TypeFor[identity.Service](),
			facade:  reflect.TypeFor[*identity.SingleTenant](),
		},
		{
			pkg:     "sessions",
			service: reflect.TypeFor[sessions.Service](),
			facade:  reflect.TypeFor[*sessions.SingleTenant](),
		},
		{
			pkg:     "mfa",
			service: reflect.TypeFor[mfa.Service](),
			facade:  reflect.TypeFor[*mfa.SingleTenant](),
		},
		{
			pkg:     "otp",
			service: reflect.TypeFor[otp.Service](),
			facade:  reflect.TypeFor[*otp.SingleTenant](),
		},
		{
			// passkey.Service is a concrete struct (not an interface); its exported methods on
			// *Service form the public API the facade mirrors.
			pkg:     "passkey",
			service: reflect.TypeFor[*passkey.Service](),
			facade:  reflect.TypeFor[*passkey.SingleTenant](),
		},
	}

	for _, tc := range cases {
		t.Run(tc.pkg, func(t *testing.T) {
			facadeMethods := exportedMethodNames(tc.facade)
			var missing []string
			for name := range exportedMethodNames(tc.service) {
				if _, ok := tc.allow[name]; ok {
					continue
				}
				if _, ok := facadeMethods[name]; !ok {
					missing = append(missing, name)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				t.Errorf("%s.SingleTenant is missing %d Service method(s): %v\n"+
					"add the delegating wrapper(s) to %s/singletenant.go (call the underlying "+
					"Service with the empty tenant \"\"), or, if a method legitimately should not "+
					"be on the facade, add it to the documented allowlist for %q in this test.",
					tc.pkg, len(missing), missing, tc.pkg, tc.pkg)
			}
		})
	}
}

// exportedMethodNames returns the set of exported method names on t. It works for both interface
// types and concrete (struct/pointer) types: reflect.Type.Method only ever reports exported
// methods, so no additional name filtering is needed.
func exportedMethodNames(t reflect.Type) map[string]struct{} {
	names := make(map[string]struct{}, t.NumMethod())
	for method := range t.Methods() {
		names[method.Name] = struct{}{}
	}
	return names
}
