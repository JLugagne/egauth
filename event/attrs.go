package event

// AttrKey names an attribute of Event.Attrs in the closed registry.
type AttrKey string

// Sensitivity classifies how an attribute may be exported.
type Sensitivity uint8

const (
	// Public attributes may go to any sink.
	Public Sensitivity = iota + 1
	// PII attributes identify a person and are dropped from public exports.
	PII
	// Secret attributes must never leave the process.
	Secret
)

// String returns the lowercase name of s, or "invalid".
func (s Sensitivity) String() string {
	switch s {
	case Public:
		return "public"
	case PII:
		return "pii"
	case Secret:
		return "secret"
	}
	return "invalid"
}

const (
	KeyMethod          AttrKey = "method"
	KeyAMR             AttrKey = "amr"
	KeyRememberMe      AttrKey = "remember_me"
	KeyInterim         AttrKey = "interim"
	KeyMustChange      AttrKey = "must_change_password"
	KeyReason          AttrKey = "reason"
	KeyCount           AttrKey = "count"
	KeyFamily          AttrKey = "family"
	KeyProvider        AttrKey = "provider"
	KeyEndpoint        AttrKey = "endpoint"
	KeyDeliveryID      AttrKey = "delivery_id"
	KeyIdentifierKind  AttrKey = "identifier_kind"
	KeyFactorChange    AttrKey = "factor_change"
	KeyRotationReason  AttrKey = "rotation_reason"
	KeyIP              AttrKey = "ip"
	KeyUserAgent       AttrKey = "user_agent"
	KeyPreviousEmail   AttrKey = "previous_email"
	KeyNewEmail        AttrKey = "new_email"
	KeyRecoveryChannel AttrKey = "recovery_channel"
	KeyKeyType         AttrKey = "key_type"
	KeyKeyID           AttrKey = "key_id"
	KeyCreatedBy       AttrKey = "created_by"
	KeyHost            AttrKey = "host"
	KeyFactor          AttrKey = "factor"
	KeyPurpose         AttrKey = "purpose"
	// KeyFlowID is the correlation id of a legacy MFA flow; it is not the flow token.
	KeyFlowID  AttrKey = "flow_id"
	KeyFactors AttrKey = "factors"
	// KeyCaptchaToken carries EndpointRequest.CaptchaToken; it is Secret so that no sink ever
	// exports it (NEW-hook-secrets).
	KeyCaptchaToken AttrKey = "captcha_token"
)

// AttrKeys returns every registered attribute key.
func AttrKeys() []AttrKey {
	return []AttrKey{
		KeyMethod, KeyAMR, KeyRememberMe, KeyInterim, KeyMustChange, KeyReason, KeyCount, KeyFamily,
		KeyProvider, KeyEndpoint, KeyDeliveryID, KeyIdentifierKind, KeyFactorChange, KeyRotationReason,
		KeyIP, KeyUserAgent, KeyPreviousEmail, KeyNewEmail, KeyRecoveryChannel, KeyKeyType, KeyKeyID,
		KeyCreatedBy, KeyHost, KeyFactor, KeyPurpose, KeyFlowID, KeyFactors, KeyCaptchaToken,
	}
}

// Registered reports whether k is declared in the registry. An emitter must refuse an unregistered
// key rather than rely on its fail-closed Secret class.
func (k AttrKey) Registered() bool {
	switch k {
	case KeyMethod, KeyAMR, KeyRememberMe, KeyInterim, KeyMustChange, KeyReason, KeyCount, KeyFamily,
		KeyProvider, KeyEndpoint, KeyDeliveryID, KeyIdentifierKind, KeyFactorChange, KeyRotationReason,
		KeyIP, KeyUserAgent, KeyPreviousEmail, KeyNewEmail, KeyRecoveryChannel, KeyKeyType, KeyKeyID,
		KeyCreatedBy, KeyHost, KeyFactor, KeyPurpose, KeyFlowID, KeyFactors, KeyCaptchaToken:
		return true
	}
	return false
}

// Sensitivity returns the export class of k. An unregistered key is Secret so that it fails closed.
func (k AttrKey) Sensitivity() Sensitivity {
	switch k {
	case KeyMethod, KeyAMR, KeyRememberMe, KeyInterim, KeyMustChange, KeyReason, KeyCount, KeyFamily,
		KeyProvider, KeyEndpoint, KeyDeliveryID, KeyIdentifierKind, KeyFactorChange, KeyRotationReason,
		KeyKeyType, KeyKeyID, KeyHost, KeyFactor, KeyPurpose, KeyFlowID, KeyFactors:
		return Public
	case KeyIP, KeyUserAgent, KeyPreviousEmail, KeyNewEmail, KeyRecoveryChannel, KeyCreatedBy:
		return PII
	case KeyCaptchaToken:
		return Secret
	}
	return Secret
}
