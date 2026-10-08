package tokens_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	tokensstore "github.com/JLugagne/egauth/adapters/pgx/store/tokens"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/tokens"
)

type legacyKey struct {
	id        uuid.UUID
	userID    uuid.UUID
	createdBy *uuid.UUID
	kind      string
	claims    string
	hash      []byte
}

func seedLegacyKey(t *testing.T, k legacyKey) {
	t.Helper()
	_, err := shared.pool.Exec(context.Background(), `INSERT INTO tokens (id, tenant_id, token_hash, user_id, prefix, claims, type, created_by)
VALUES ($1, 't', $2, $3, 'egk_', $4::jsonb, $5, $6)`, k.id, hex.EncodeToString(k.hash), k.userID, k.claims, k.kind, k.createdBy)
	require.NoError(t, err)
}

func legacyHash(seed string) []byte {
	sum := sha256.Sum256([]byte("v016-api-key-" + seed))
	return sum[:]
}

func decodeClaims(t *testing.T, b []byte) map[string][]string {
	t.Helper()
	var out map[string][]string
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

func TestLegacyAPIKeysAreOwnedByTheirCreator(t *testing.T) {
	s := tokensstore.New(cleanPool(t))
	ctx := context.Background()
	tn, err := principal.ParseTenantID("t")
	require.NoError(t, err)
	creator := principal.Subject{Tenant: tn, User: uuid.New()}
	service := legacyKey{id: uuid.New(), createdBy: &creator.User, kind: "service", hash: legacyHash("service"),
		claims: `{"Subject":"x","TenantID":"t","Roles":["deploy"],"Scopes":["read"],"Groups":null,"AMR":["mfa"],"Custom":{"admin":true}}`}
	service.userID = service.id
	pat := legacyKey{id: uuid.New(), userID: creator.User, createdBy: &creator.User, kind: "pat", hash: legacyHash("pat"),
		claims: `{"roles":["deploy"]}`}
	orphan := legacyKey{id: uuid.New(), kind: "service", hash: legacyHash("orphan"), claims: `{"Roles":["deploy"]}`}
	orphan.userID = orphan.id
	for _, k := range []legacyKey{service, pat, orphan} {
		seedLegacyKey(t, k)
	}

	got, err := s.GetAPIKey(ctx, tn, service.hash)
	require.NoError(t, err)
	require.Equal(t, creator, got.Owner, "a v0.16 service key is owned by its creator, not by its own id")
	require.Equal(t, service.id, got.ID)
	require.Equal(t, "service", got.Kind)
	require.Equal(t, map[string][]string{"roles": {"deploy"}, "scopes": {"read"}, "groups": {}}, decodeClaims(t, got.AppClaims),
		"the v0.16 authority is carried as the requested subset, without AMR, subject or custom claims")
	gotPAT, err := s.GetAPIKey(ctx, tn, pat.hash)
	require.NoError(t, err)
	require.Equal(t, creator, gotPAT.Owner)
	require.Equal(t, map[string][]string{"roles": {"deploy"}, "scopes": {}, "groups": {}}, decodeClaims(t, gotPAT.AppClaims))
	gotOrphan, err := s.GetAPIKey(ctx, tn, orphan.hash)
	require.NoError(t, err)
	require.Equal(t, orphan.id, gotOrphan.Owner.User, "a key with no recorded creator keeps an owner no account has")

	list, err := s.ListAPIKeys(ctx, creator)
	require.NoError(t, err)
	ids := []uuid.UUID{}
	for _, k := range list {
		ids = append(ids, k.ID)
	}
	require.ElementsMatch(t, []uuid.UUID{service.id, pat.id}, ids)

	require.NoError(t, s.RevokeAPIKey(ctx, creator, service.id))
	got, err = s.GetAPIKey(ctx, tn, service.hash)
	require.NoError(t, err)
	require.False(t, got.RevokedAt.IsZero(), "the creator revokes a v0.16 service key")
	require.ErrorIs(t, s.RevokeAPIKey(ctx, principal.Subject{Tenant: tn, User: service.id}, service.id), store.ErrNotFound,
		"the key id is not an owner")

	require.NoError(t, s.DeleteForSubject(ctx, creator))
	for _, h := range [][]byte{service.hash, pat.hash} {
		_, err := s.GetAPIKey(ctx, tn, h)
		require.ErrorIs(t, err, store.ErrNotFound, "deleting the creator erases its v0.16 keys")
	}
	_, err = s.GetAPIKey(ctx, tn, orphan.hash)
	require.NoError(t, err)
}

func TestNewAPIKeysAreNotMistakenForLegacyOnes(t *testing.T) {
	s := tokensstore.New(cleanPool(t))
	ctx := context.Background()
	tn, err := principal.ParseTenantID("t")
	require.NoError(t, err)
	owner := principal.Subject{Tenant: tn, User: uuid.New()}
	now := time.Now().UTC().Truncate(time.Microsecond)
	k := tokens.APIKey{ID: uuid.New(), Owner: owner, Kind: "automation", KeyHash: legacyHash("new"), CreatedAt: now}
	require.NoError(t, s.CreateAPIKey(ctx, k))
	got, err := s.GetAPIKey(ctx, tn, k.KeyHash)
	require.NoError(t, err)
	require.Nil(t, got.AppClaims, "a key created with no claims subset reads back without one")
	require.Equal(t, owner, got.Owner)
}

func TestReapRemovesExpiredLegacyRefreshRows(t *testing.T) {
	pool := cleanPool(t)
	s := tokensstore.New(pool)
	ctx := context.Background()
	user := uuid.New()
	for i, exp := range []time.Duration{-time.Hour, time.Hour} {
		_, err := pool.Exec(ctx, `INSERT INTO tokens (id, tenant_id, token_hash, user_id, family_id, expires_at)
VALUES ($1, 't', $2, $3, $4, now() + $5::bigint * interval '1 microsecond')`,
			uuid.New(), hex.EncodeToString(legacyHash("refresh-"+string(rune('a'+i)))), user, uuid.New(), exp.Microseconds())
		require.NoError(t, err)
	}
	_, err := s.ReapExpired(ctx)
	require.NoError(t, err)
	var left int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM tokens WHERE claims IS NULL AND expires_at > now()`).Scan(&left))
	require.Equal(t, 1, left, "an unexpired v0.16 refresh row is kept for v0.16 replicas")
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM tokens WHERE claims IS NULL`).Scan(&left))
	require.Equal(t, 1, left, "an expired v0.16 refresh row is reaped")
}

func TestConsumptionAfterALockWaitUsesTheStatementTime(t *testing.T) {
	pool := cleanPool(t)
	s := tokensstore.New(pool)
	ctx := context.Background()
	tn, err := principal.ParseTenantID("t")
	require.NoError(t, err)
	sub := principal.Subject{Tenant: tn, User: uuid.New()}
	lineage, family := uuid.New(), uuid.New()
	a := record(t, sub, lineage, family, "client", 7)
	require.NoError(t, s.Create(ctx, a))

	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback(ctx) }()
	_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"egauth/tokens/subject/"+tn.String()+"/"+sub.User.String())
	require.NoError(t, err)

	type result struct {
		rot tokens.Rotation
		err error
	}
	next := record(t, sub, lineage, family, "client", 8)
	done := make(chan result, 1)
	go func() {
		rot, err := s.ConsumeForRotation(ctx, tokens.RotationRequest{Presented: a.TokenHash(), Next: next})
		done <- result{rot, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("the rotation did not wait for the subject lock: %v", r.err)
	case <-time.After(1500 * time.Millisecond):
	}
	var released time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&released))
	require.NoError(t, holder.Commit(ctx))
	r := <-done
	require.NoError(t, r.err)
	require.False(t, r.rot.ConsumedAt.Before(released.Truncate(time.Microsecond)),
		"consumed_at %s predates the end of the lock wait %s", r.rot.ConsumedAt, released)
}
