// Tests that every shared response-writing helper marks the response uncacheable.
// Auth endpoints write Set-Cookie and token material on their responses, and OWASP
// session-management guidance requires Cache-Control: no-store on such responses so
// shared caches/CDNs can never store them (RFC 9111 §3.2).

package httputil_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/internal/httputil"
	"github.com/stretchr/testify/assert"
)

func TestWriteJSON_SetsNoStore(t *testing.T) {
	rec := httptest.NewRecorder()
	httputil.WriteJSON(rec, http.StatusOK, map[string]string{"ok": "1"})

	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestFail_SetsNoStore(t *testing.T) {
	t.Run("plain error branch", func(t *testing.T) {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		httputil.Fail(rec, r, "", http.StatusBadRequest, "bad_request")

		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("redirect branch", func(t *testing.T) {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		httputil.Fail(rec, r, "https://app.example.com/failure", http.StatusSeeOther, "bad_request")

		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.NotEmpty(t, rec.Header().Get("Location"))
	})
}

func TestRedirectOrStatus_SetsNoStore(t *testing.T) {
	t.Run("redirect branch", func(t *testing.T) {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		httputil.RedirectOrStatus(rec, r, "https://app.example.com/done", http.StatusNoContent)

		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.NotEmpty(t, rec.Header().Get("Location"))
	})

	t.Run("status branch", func(t *testing.T) {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		httputil.RedirectOrStatus(rec, r, "", http.StatusNoContent)

		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})
}
