package routes

import "testing"

func TestEveryRegisteredPathIsClassifiedForSPA(t *testing.T) {
	for _, p := range All() {
		if _, ok := spaAllowed[p]; !ok {
			t.Errorf("%s has no SPA classification: add it to spaAllowed", p)
		}
	}
	for p := range spaAllowed {
		if Method(p) == "" {
			t.Errorf("%q is classified but is not a registered path", p)
		}
	}
}

func TestCredentialReturningRoutesStaySameOrigin(t *testing.T) {
	for _, p := range []string{ResourceToken, MFATOTPEnroll, MFATOTPConfirm, MFARecoveryCodesRegenerate} {
		if spaAllowed[p] {
			t.Errorf("%s returns a credential but is exposed to SPA origins", p)
		}
	}
}
