package passkey_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFinishLogin_OversizedBodyRejected proves DOS-01 is fixed: a Finish request whose body
// exceeds the configured cap is rejected before the go-webauthn decoder buffers and
// base64-decodes it. Before the fix (no http.MaxBytesReader in the handler) the same body is
// read in full and parsed, so the handler would not reject it on size.
func TestFinishLogin_OversizedBodyRejected(t *testing.T) {
	svc := newPasskeyService(t)
	uid := uuid.New()
	auth := registerTenant(t, svc, "t1", uid)

	baseOpts := []passkey.HandlerOption{
		resolver(uid),
		passkey.WithCookieKey(testCookieKey),
	}

	// Capture a genuine, well-formed Finish body so the only failing condition under test is
	// the size cap (not a malformed assertion).
	cookie, body := beginLoginAndCaptureFinish(t, svc, uid, auth, baseOpts...)
	require.NotEmpty(t, body)

	// Cap the body below its real length: http.MaxBytesReader truncates the stream, so the
	// webauthn decode fails and the handler returns a 4xx via cfg.fail.
	cap := int64(len(body) - 1)
	opts := append([]passkey.HandlerOption{passkey.WithMaxBodyBytes(cap)}, baseOpts...)

	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	passkey.FinishLoginHandler(svc, opts...)(rec, req)

	assert.GreaterOrEqual(t, rec.Code, http.StatusBadRequest,
		"an oversized Finish body must be rejected, not parsed")
	assert.Less(t, rec.Code, http.StatusInternalServerError,
		"truncation by the body cap is a client error (4xx), not a server error")
}

// TestFinishLogin_NormalBodyAccepted is the positive control: a legitimately sized Finish
// body still succeeds under the default cap.
func TestFinishLogin_NormalBodyAccepted(t *testing.T) {
	svc := newPasskeyService(t)
	uid := uuid.New()
	auth := registerTenant(t, svc, "t1", uid)

	opts := []passkey.HandlerOption{
		resolver(uid),
		passkey.WithCookieKey(testCookieKey),
	}

	cookie, body := beginLoginAndCaptureFinish(t, svc, uid, auth, opts...)
	require.Less(t, int64(len(body)), passkey.DefaultMaxBodyBytes,
		"a real ceremony body must fit comfortably under the default cap")

	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	passkey.FinishLoginHandler(svc, opts...)(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code,
		"a normally sized valid Finish body must still succeed")
}
