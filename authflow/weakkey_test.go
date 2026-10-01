package authflow

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// F-AFLOW-002 regression: NewEngine must refuse HMAC keys an attacker can reconstruct
// (all-zero, repeated byte, published example literals, marker-bearing near-copies) exactly
// like tokens/jwt's signer constructors do. With such a key an attacker forges a
// StateMFAChallenged flow token for any principal and drives step-up.
func TestNewEngine_RejectsKnownHMACKeys(t *testing.T) {
	known := map[string][]byte{
		"all zero":          make([]byte, 32),
		"repeated byte":     bytes.Repeat([]byte{0xAB}, 32),
		"published HS256":   []byte("super-secret-32-byte-key-here!!!"),
		"published passkey": []byte("very-secure-32-byte-secret-key!!"),
		"marker near-copy":  []byte("minimum-hs256-signing-secret!!!!"),
	}
	for name, key := range known {
		t.Run(name, func(t *testing.T) {
			engine, err := NewEngine(key)
			require.Error(t, err, "NewEngine accepted an attacker-known key")
			require.Nil(t, engine, "a rejected key must not yield a usable engine")
		})
	}
}

// TestNewEngine_AcceptsANonTrivialKey is the control: normal operator material still works.
func TestNewEngine_AcceptsANonTrivialKey(t *testing.T) {
	engine, err := NewEngine([]byte("01234567890123456789012345678901"))
	require.NoError(t, err)
	require.NotNil(t, engine)
}

// TestNewEngine_TrivialKeyCannotForgeFlowSessions mirrors the audit PoC: if construction ever
// accepted the all-zero key again, a token forged with that key would be accepted by
// ProcessStepUp and mint a session for the attacker-chosen principal.
func TestNewEngine_TrivialKeyCannotForgeFlowSessions(t *testing.T) {
	key := make([]byte, 32)

	minter := &weakKeyMinter{}
	engine, err := NewEngine(key, WithMinter(minter), WithAccountValidator(&weakKeyValidator{}))
	if err != nil {
		return // the key was refused at construction: the forgery primitive is gone
	}

	forged, ferr := encodeFlowToken(&FlowContext{
		FlowID:    "forged-by-auditor",
		TenantID:  "victim-tenant",
		UserID:    uuid.New(),
		State:     StateMFAChallenged,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, key)
	require.NoError(t, ferr)

	form := url.Values{"code": {"123456"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/step-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+req.Host)
	req.AddCookie(&http.Cookie{Name: DefaultFlowCookieName, Value: forged})

	_, serr := engine.ProcessStepUp(context.Background(), httptest.NewRecorder(), req, forged, "totp", []string{tokens.AMROTP})
	t.Fatalf("NewEngine accepted an all-zero HMAC key; forged flow token accepted by ProcessStepUp (mints=%d, err=%v)", minter.calls, serr)
}

type weakKeyMinter struct{ calls int }

func (m *weakKeyMinter) Mint(ctx context.Context, w http.ResponseWriter, r *http.Request, flow *FlowContext) error {
	m.calls++
	return nil
}

type weakKeyValidator struct{}

func (v *weakKeyValidator) ValidateAccount(ctx context.Context, tenantID string, userID uuid.UUID) error {
	return nil
}
