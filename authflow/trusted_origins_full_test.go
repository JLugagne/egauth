package authflow_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/authflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStepUpHandler_WithTrustedOrigins_AcceptsFullOrigin pins issue #124 for the authflow
// step-up handler.
func TestStepUpHandler_WithTrustedOrigins_AcceptsFullOrigin(t *testing.T) {
	engine, minter, v, flowToken := challengedFlow(t)
	h := authflow.StepUpHandler(engine, v, authflow.WithTrustedOrigins("https://web.example.com"))

	rec := httptest.NewRecorder()
	h(rec, originCheckRequest(flowToken, "app.example.com", "https://web.example.com", false))
	assert.Equal(t, http.StatusNoContent, rec.Code, "a full-origin entry must pass the origin check")
	require.Len(t, minter.mintedFlows, 1)
}

// TestStepUpHandler_WithTrustedOrigins_FullOriginLookalikeStillRejected pins exact matching.
func TestStepUpHandler_WithTrustedOrigins_FullOriginLookalikeStillRejected(t *testing.T) {
	engine, _, v, flowToken := challengedFlow(t)
	h := authflow.StepUpHandler(engine, v, authflow.WithTrustedOrigins("https://web.example.com"))

	rec := httptest.NewRecorder()
	h(rec, originCheckRequest(flowToken, "app.example.com", "https://web.example.com.evil.com", false))
	assert.Equal(t, http.StatusForbidden, rec.Code, "normalization must not become suffix matching")
}
