package event_test

import (
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/routes"
)

func TestV17TypesAreUniqueAndDoNotCollideWithLegacy(t *testing.T) {
	legacy := []event.Type{
		event.LoginSucceeded, event.LoginFailed, event.SessionIssued, event.AccountLocked, event.UserRegistered,
		event.PasswordReset, event.PasswordChanged, event.EmailVerified, event.EmailChanged, event.PhoneVerified,
		event.RecoveryChannelEnrolled, event.AccountDeleted, event.Logout, event.AccountBlocked,
		event.AccountDisabled, event.AccountEnabled, event.RefreshReuseDetected, event.TokenFamilyRevoked,
		event.MFAChallengeRequired, event.MFAEnrolled, event.MFAConfirmed, event.MFAVerified,
		event.MFAVerificationFailed, event.MFADisabled, event.MFAUnlocked, event.CredentialAdded,
		event.CredentialRemoved, event.DeliveryFailed, event.InsecureCookieMisuse, event.RedirectFallbackMisuse,
		event.APIKeyCreated, event.APIKeyRevoked, event.APIKeyAuthSucceeded, event.APIKeyAuthFailed, event.APIKeyPurged,
	}
	seen := map[event.Type]bool{}
	for _, l := range legacy {
		seen[l] = true
	}
	for _, v := range event.V17Types() {
		if v == "" || seen[v] {
			t.Fatalf("type %q empty or colliding", v)
		}
		seen[v] = true
	}
}

func TestAttrKeysAreClassified(t *testing.T) {
	seen := map[event.AttrKey]bool{}
	for _, k := range event.AttrKeys() {
		if k == "" || seen[k] {
			t.Fatalf("key %q empty or duplicated", k)
		}
		seen[k] = true
		if !k.Registered() {
			t.Fatalf("key %q is listed but not registered", k)
		}
		if s := k.Sensitivity(); s != event.Public && s != event.PII && s != event.Secret {
			t.Fatalf("key %q has no explicit class", k)
		}
	}
	if event.KeyIP.Sensitivity() != event.PII || event.KeyReason.Sensitivity() != event.Public {
		t.Fatal("unexpected classification")
	}
	if event.KeyCaptchaToken.Sensitivity() != event.Secret || string(event.KeyCaptchaToken) != routes.FieldCaptchaToken {
		t.Fatal("the captcha token must be a registered Secret key (NEW-hook-secrets)")
	}
	for k, want := range map[string]event.Sensitivity{
		"key_type": event.Public, "key_id": event.Public, "created_by": event.PII, "host": event.Public,
		"factor": event.Public, "purpose": event.Public, "flow_id": event.Public, "factors": event.Public,
	} {
		if !seen[event.AttrKey(k)] || event.AttrKey(k).Sensitivity() != want {
			t.Errorf("legacy attribute %q must be registered as %s", k, want)
		}
	}
	if u := event.AttrKey("unregistered"); u.Registered() || u.Sensitivity() != event.Secret {
		t.Fatal("an unregistered key must fail closed")
	}
	if event.Sensitivity(0).String() != "invalid" || event.PII.String() != "pii" {
		t.Fatal("unexpected sensitivity names")
	}
	if string(event.KeyIP) != event.AttrIP || string(event.KeyUserAgent) != event.AttrUserAgent ||
		string(event.KeyPreviousEmail) != event.AttrPreviousEmail || string(event.KeyNewEmail) != event.AttrNewEmail ||
		string(event.KeyRecoveryChannel) != event.AttrRecoveryChannel {
		t.Fatal("registry keys must equal the legacy attribute strings")
	}
}
