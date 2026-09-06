package authflow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// encodeFlowToken serializes and signs a FlowContext into a tamper-evident compact string.
func encodeFlowToken(flow *FlowContext, secret []byte) (string, error) {
	payload, err := json.Marshal(flow)
	if err != nil {
		return "", fmt.Errorf("marshal flow context: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payloadB64 + "." + sigB64, nil
}

// decodeFlowToken validates signature and expiration, deserializing the FlowContext.
func decodeFlowToken(tokenStr string, secret []byte, now time.Time) (*FlowContext, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 2 {
		return nil, ErrInvalidFlowToken
	}

	payloadB64, sigB64 := parts[0], parts[1]
	expectedSig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrInvalidFlowToken
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	actualSig := mac.Sum(nil)

	if !hmac.Equal(actualSig, expectedSig) {
		return nil, ErrInvalidFlowToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrInvalidFlowToken
	}

	var flow FlowContext
	if err := json.Unmarshal(payload, &flow); err != nil {
		return nil, ErrInvalidFlowToken
	}

	if !flow.ExpiresAt.IsZero() && now.After(flow.ExpiresAt) {
		return nil, ErrFlowTokenExpired
	}

	return &flow, nil
}
