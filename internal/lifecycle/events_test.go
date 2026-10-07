package lifecycle_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/JLugagne/egauth/internal/lifecycle"
)

type noopSubscriber struct{}

func (noopSubscriber) OnCredentialRotated(context.Context, lifecycle.CredentialRotated) error {
	return nil
}
func (noopSubscriber) OnFactorsChanged(context.Context, lifecycle.FactorsChanged) error { return nil }
func (noopSubscriber) OnIdentifierChanged(context.Context, lifecycle.IdentifierChanged) error {
	return nil
}
func (noopSubscriber) OnDisabled(context.Context, lifecycle.AccountEvent) error     { return nil }
func (noopSubscriber) OnEnabled(context.Context, lifecycle.AccountEvent) error      { return nil }
func (noopSubscriber) OnDeleted(context.Context, lifecycle.AccountEvent) error      { return nil }
func (noopSubscriber) OnTenantErased(context.Context, lifecycle.TenantErased) error { return nil }
func (noopSubscriber) OnSessionEnded(context.Context, lifecycle.SessionEnded) error { return nil }

var _ lifecycle.Subscriber = noopSubscriber{}

func TestSubscriberHasOneMethodPerEvent(t *testing.T) {
	if n := reflect.TypeFor[lifecycle.Subscriber]().NumMethod(); n != 8 {
		t.Fatalf("want 8 subscriber methods, got %d", n)
	}
}

func TestLifecycleEnumValuesArePinned(t *testing.T) {
	reasons := map[lifecycle.RotationReason]string{
		1: "password_changed", 2: "password_reset", 3: "temporary_password", 4: "security_revert",
	}
	for r, name := range reasons {
		if r.String() != name {
			t.Errorf("rotation reason %d: got %q, want %q", r, r.String(), name)
		}
	}
	changes := map[lifecycle.FactorChange]string{
		1: "totp_enrolled", 2: "totp_disabled", 3: "recovery_codes_regenerated", 4: "passkey_added",
		5: "passkey_removed", 6: "federated_linked", 7: "federated_unlinked",
	}
	for c, name := range changes {
		if c.String() != name {
			t.Errorf("factor change %d: got %q, want %q", c, c.String(), name)
		}
	}
	kinds := map[lifecycle.IdentifierKind]string{1: "email", 2: "phone", 3: "recovery_email"}
	for k, name := range kinds {
		if k.String() != name {
			t.Errorf("identifier kind %d: got %q, want %q", k, k.String(), name)
		}
	}
	if lifecycle.RotationReason(0).String() != "invalid" || lifecycle.FactorChange(0).String() != "invalid" ||
		lifecycle.IdentifierKind(0).String() != "invalid" || lifecycle.RotationReason(5).String() != "invalid" ||
		lifecycle.FactorChange(8).String() != "invalid" || lifecycle.IdentifierKind(4).String() != "invalid" {
		t.Fatal("undeclared values must be invalid")
	}
}

func TestFederationLinkChangesAreFactorChanges(t *testing.T) {
	if lifecycle.FactorFederatedLinked == lifecycle.FactorFederatedUnlinked ||
		lifecycle.FactorFederatedLinked.String() == "invalid" || lifecycle.FactorFederatedUnlinked.String() == "invalid" {
		t.Fatal("federation link and unlink must be distinct, named factor changes")
	}
}
