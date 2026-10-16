package e2e_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/adapters/pgx/pgxstore"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
)

const (
	aliceID        = "6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5"
	aliceEmail     = "alice@example.test"
	aliceTOTP      = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	legacyAPIKey   = "egk_v016-api-key-secret"
	legacySession  = "v016-session-secret"
	legacyKeyID    = "k-fixture-1"
	legacyKeyBytes = "signing-key-material-for-fixture-0001"
)

var legacyRefreshTokens = []string{"v016-refresh-live", "v016-refresh-consumed", "v016-refresh-laundered"}

func legacyFixtureKey(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "v016_key.hex"))
	require.NoError(t, err)
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	return key
}

func loadDump(ctx context.Context, t *testing.T, db pgxstore.MigrationDB) {
	t.Helper()
	sql, err := os.ReadFile(filepath.Join("testdata", "v016.sql"))
	require.NoError(t, err)
	_, err = db.Exec(ctx, string(sql))
	require.NoError(t, err)
}

func totpCode(secret string, at time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

func legacyJWT(t *testing.T) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": legacyKeyID})
	require.NoError(t, err)
	claims, err := json.Marshal(map[string]any{
		"sub": aliceID, "tenant_id": e2eTenant, "amr": []string{"pwd", "mfa"},
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	input := enc(header) + "." + enc(claims)
	mac := hmac.New(sha256.New, []byte(legacyKeyBytes))
	mac.Write([]byte(input))
	return input + "." + enc(mac.Sum(nil))
}

func jsonField(t *testing.T, body []byte, key string) string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m), string(body))
	s, _ := m[key].(string)
	return s
}

func TestG29LegacyUpgrade(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	loadDump(ctx, t, pool)

	require.NoError(t, pgxstore.Migrate(ctx, pool))
	var applied int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM egauth_schema_migrations`).Scan(&applied))
	require.NoError(t, pgxstore.Migrate(ctx, pool), "a second Migrate is a no-op")
	var again int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM egauth_schema_migrations`).Scan(&again))
	require.Equal(t, applied, again)

	newKey := newKEK(t)
	_, err := buildAuth(ctx, t, pool, newKey)
	require.Error(t, err, "New refuses to start while v0.16 secrets remain")
	require.Contains(t, err.Error(), "UpgradeSecretsV016")
	require.Contains(t, err.Error(), "UpgradeIdentifiersV016", "and while v0.16 identifiers are unchecked")

	st, err := pgxstore.New(ctx, pool)
	require.NoError(t, err)
	legacy, err := kek.LegacyLocalV016(legacyFixtureKey(t))
	require.NoError(t, err)
	first, err := egauth.UpgradeSecretsV016(ctx, st, legacy, newKey)
	require.NoError(t, err)
	require.Equal(t, 3, first.Upgraded, "one TOTP secret, one OAuth client secret and one tenant key")
	require.Empty(t, first.Unopenable)
	second, err := egauth.UpgradeSecretsV016(ctx, st, legacy, newKey)
	require.NoError(t, err)
	require.Equal(t, 0, second.Upgraded, "a second upgrade finds nothing to do")
	require.Empty(t, second.Unopenable)
	for _, table := range []string{"mfa_totp", "oauth_oidc_providers", "keystore_keys"} {
		var legacyLeft int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE aad_version = 0`).Scan(&legacyLeft))
		require.Zero(t, legacyLeft, table)
	}

	ids, err := egauth.UpgradeIdentifiersV016(ctx, st)
	require.NoError(t, err)
	require.Equal(t, egauth.IdentifierUpgradeReport{Upgraded: 2}, ids, "alice and bob are already canonical")

	auth, err := buildAuth(ctx, t, pool, newKey)
	require.NoError(t, err, "New starts once the secrets and identifiers are upgraded")
	h := serve(t, auth)

	t.Run("TOTP secret opens", func(t *testing.T) {
		login := send(h, call{method: http.MethodPost, path: "/auth" + egauth.PathLogin,
			header: http.Header{egauth.HeaderTransport: {"bearer"}},
			body:   fmt.Sprintf(`{%q:%q,%q:%q}`, egauth.FieldIdentifier, aliceEmail, egauth.FieldPassword, e2ePassword)})
		require.Equal(t, http.StatusOK, login.Code, login.Body.String())
		flow := jsonField(t, login.Body.Bytes(), "flow")
		require.NotEmpty(t, flow, login.Body.String())
		require.Empty(t, login.Header().Get("X-Egauth-Access-Token"), "password login of an MFA subject issues no interim session")
		hdr := http.Header{egauth.HeaderTransport: {"bearer"}}
		body := fmt.Sprintf(`{%q:"totp",%q:%q,%q:%q}`, egauth.FieldFactor, egauth.FieldCode, totpCode(aliceTOTP, time.Now()), egauth.FieldFlow, flow)
		done := send(h, call{method: http.MethodPost, path: "/auth" + egauth.PathMFAChallenge, header: hdr, body: body})
		require.Equal(t, http.StatusOK, done.Code, done.Body.String())
		token := done.Header().Get("X-Egauth-Access-Token")
		require.NotEmpty(t, token)
		head, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
		require.NoError(t, err)
		require.Equal(t, legacyKeyID, jsonField(t, head, "kid"), "the carried-over tenant key signs the new session")
		me := send(h, call{method: http.MethodGet, path: "/me", header: bearer(token)})
		require.Equal(t, http.StatusOK, me.Code)
		require.Equal(t, aliceID, me.Body.String())
		fresh := done.Header().Get("X-Egauth-Refresh-Token")
		require.NotEmpty(t, fresh, "positive control: the bearer refresh header name is the one the library uses")
		control := send(h, call{method: http.MethodPost, path: "/auth" + egauth.PathRefresh,
			header: http.Header{"X-Egauth-Refresh-Token": {fresh}, egauth.HeaderTransport: {"bearer"}}})
		require.Equal(t, http.StatusOK, control.Code, control.Body.String())
	})

	t.Run("legacy refresh tokens are refused", func(t *testing.T) {
		for _, secret := range legacyRefreshTokens {
			res := send(h, call{method: http.MethodPost, path: "/auth" + egauth.PathRefresh,
				header: http.Header{"X-Egauth-Refresh-Token": {secret}, egauth.HeaderTransport: {"bearer"}}})
			require.Equal(t, http.StatusUnauthorized, res.Code, secret)
		}
	})

	t.Run("legacy session handles are refused by the stateful backend", func(t *testing.T) {
		statefulAuth, err := buildAuthWith(ctx, t, pool, newKey, egauth.Stateful())
		require.NoError(t, err)
		sh := serve(t, statefulAuth)
		sessionCookie := "__Host-session"
		res := send(sh, call{method: http.MethodGet, path: "/me", header: bearer(legacySession)})
		require.Equal(t, http.StatusUnauthorized, res.Code)
		res = send(sh, call{method: http.MethodGet, path: "/me", header: http.Header{"Cookie": {sessionCookie + "=" + legacySession}}})
		require.Equal(t, http.StatusUnauthorized, res.Code)
	})

	t.Run("legacy refresh tokens are refused through the refresh cookie", func(t *testing.T) {
		name := "__Host-refresh_token"
		cookieOnly := func(value string) *httptest.ResponseRecorder {
			return send(h, call{method: http.MethodGet, path: "/me", header: http.Header{"Cookie": {name + "=" + value}}})
		}
		login := send(h, call{method: http.MethodPost, path: "/auth" + egauth.PathLogin,
			body: fmt.Sprintf(`{%q:%q,%q:%q}`, egauth.FieldIdentifier, aliceEmail, egauth.FieldPassword, e2ePassword)})
		require.Equal(t, http.StatusOK, login.Code, login.Body.String())
		body := fmt.Sprintf(`{%q:"totp",%q:%q}`, egauth.FieldFactor, egauth.FieldCode, totpCode(aliceTOTP, time.Now().Add(30*time.Second)))
		var carried []string
		for _, c := range login.Result().Cookies() {
			carried = append(carried, c.Name+"="+c.Value)
		}
		done := send(h, call{method: http.MethodPost, path: "/auth" + egauth.PathMFAChallenge, body: body,
			header: http.Header{"Cookie": {strings.Join(carried, "; ")}}})
		require.Equal(t, http.StatusOK, done.Code, done.Body.String())
		fresh := ""
		for _, c := range done.Result().Cookies() {
			if c.Name == name {
				fresh = c.Value
			}
		}
		require.NotEmpty(t, fresh, "a cookie login issues a v0.17 refresh cookie")
		require.Equal(t, http.StatusOK, cookieOnly(fresh).Code, "positive control: a fresh refresh cookie alone renews on a protected route")
		for _, secret := range legacyRefreshTokens {
			require.Equal(t, http.StatusUnauthorized, cookieOnly(secret).Code, secret)
		}
	})

	t.Run("a legacy access JWT signed with the carried-over tenant key is refused", func(t *testing.T) {
		res := send(h, call{method: http.MethodGet, path: "/me", header: bearer(legacyJWT(t))})
		require.Equal(t, http.StatusUnauthorized, res.Code)
	})

	t.Run("legacy API keys keep working", func(t *testing.T) {
		res := send(h, call{method: http.MethodGet, path: "/api/report", header: bearer(legacyAPIKey)})
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		res = send(h, call{method: http.MethodGet, path: "/api/report", header: bearer(legacyAPIKey + "x")})
		require.Equal(t, http.StatusUnauthorized, res.Code)
	})

	t.Run("OAuth client secret opens under the current KEK and the legacy opener no longer does", func(t *testing.T) {
		tenant, err := principal.ParseTenantID(e2eTenant)
		require.NoError(t, err)
		spec, err := st.Federation.GetProvider(ctx, tenant, "google")
		require.NoError(t, err)
		aad := kek.AAD("egauth/oauth-client-secret/v1\x00" + tenant.String() + "\x00google")
		plaintext, err := newKey.Open(ctx, spec.SealedSecret, aad)
		require.NoError(t, err)
		require.Equal(t, "client-secret-value-for-fixture", string(plaintext))
		keyID, err := newKey.KeyIDOf(spec.SealedSecret)
		require.NoError(t, err)
		require.Equal(t, newKey.CurrentKeyID(), keyID)
		_, err = legacy.OpenLegacy(ctx, spec.SealedSecret, nil)
		require.Error(t, err)
	})
}
