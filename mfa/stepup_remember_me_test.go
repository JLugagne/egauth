package mfa_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/mfa/memory"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStepUpHandler_RememberMe_InheritedFromInterim(t *testing.T) {
	for _, remember := range []bool{true, false} {
		t.Run(map[bool]string{true: "remembered", false: "session"}[remember], func(t *testing.T) {
			clk := &clock{t: time.Unix(1_700_000_000, 0)}
			svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
			uid := uuid.Must(uuid.NewV7())
			resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
			secret := seedConfirmedEnrollment(t, svc, resolver, clk)

			var captured tokens.Claims[struct{}]
			issuer := mustChangeStepUpIssuer(&captured)
			builder := func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
				return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
			}

			interim := interimClaims(uid, "t1", false)
			interim.RememberMe = remember

			clk.t = clk.t.Add(mfa.DefaultPeriod)
			rec := httptest.NewRecorder()
			h := contextVerifying(interim, mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver, mfa.WithInsecureEchoSessionState()))
			req := mfaPost(url.Values{"code": {clk.code(t, secret)}})
			req.Header.Set("Authorization", "Bearer interim-access-jwt")
			h.ServeHTTP(rec, req)

			require.Equal(t, http.StatusNoContent, rec.Code)
			assert.Equal(t, remember, captured.RememberMe, "the stepped-up family must record the login's remember_me choice")
			refresh := stepUpCookie(rec, tokens.DefaultRefreshCookieName)
			require.NotNil(t, refresh)
			if remember {
				assert.Positive(t, refresh.MaxAge, "a remembered login must get a persistent refresh cookie after step-up")
			} else {
				assert.Zero(t, refresh.MaxAge, "a session login must keep a session refresh cookie after step-up")
			}
		})
	}
}
