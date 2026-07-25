package pgx

import (
	"context"
	"errors"
	"time"

	"github.com/JLugagne/egauth/passkey"
	"github.com/jackc/pgx/v5"
)

// ChallengeStore is the PostgreSQL-backed passkey.ChallengeStore: the SHARED, single-use store a
// multi-replica deployment needs. The in-memory reference implementation
// (github.com/JLugagne/egauth/passkey/memory) keeps its map per process, so a ceremony begun on one
// pod cannot be finished on another — roughly (N-1)/N of the ceremonies of an N-replica deployment
// are rejected as replays. Back Config.ChallengeStore with this store instead of reaching for
// Config.InsecureNoChallengeStore, which removes the SEC-05 replay defence outright.
//
// Consume is a single DELETE ... RETURNING, so it is atomic across processes: exactly one of N
// racing Finish requests carrying the same challenge succeeds.
type ChallengeStore struct {
	db DBQuerier
}

// NewChallengeStore creates a PostgreSQL-backed passkey challenge store over db. Apply Migrate
// first: the challenge table ships with the passkey module's migrations.
func NewChallengeStore(db DBQuerier) *ChallengeStore {
	return &ChallengeStore{db: db}
}

// Put records an issued challenge with an absolute expiry, scoped to tenantID (the empty string is
// the single-tenant partition). Re-recording the same (tenantID, challenge) refreshes its expiry
// rather than failing, so a retried Begin cannot strand the ceremony.
func (s *ChallengeStore) Put(ctx context.Context, tenantID, challenge string, expiresAt time.Time) error {
	const query = `
		INSERT INTO passkey_challenges (tenant_id, challenge, expires_at, created_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (tenant_id, challenge) DO UPDATE
		SET expires_at = EXCLUDED.expires_at, created_at = EXCLUDED.created_at
	`
	if _, err := s.db.Exec(ctx, query, tenantID, challenge, expiresAt.UTC()); err != nil {
		return errors.Join(errors.New("pgx passkey: record ceremony challenge"), err)
	}
	return nil
}

// Consume atomically removes the challenge and reports whether it was present and unexpired. A
// second Consume of the same challenge returns (false, nil), including when the two run
// concurrently on different replicas: the delete is what decides the winner. An expired row is
// deleted too, and reported as false, so a stale entry cannot linger or be reused.
func (s *ChallengeStore) Consume(ctx context.Context, tenantID, challenge string) (bool, error) {
	const query = `
		DELETE FROM passkey_challenges
		WHERE tenant_id = $1 AND challenge = $2
		RETURNING expires_at
	`
	var expiresAt time.Time
	err := s.db.QueryRow(ctx, query, tenantID, challenge).Scan(&expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.Join(errors.New("pgx passkey: consume ceremony challenge"), err)
	}
	return time.Now().Before(expiresAt), nil
}

// DeleteExpired purges every expired challenge across all tenants and returns how many rows it
// removed. A ceremony that is never finished leaves its row behind until it is pruned — Consume
// only reclaims challenges someone comes back for — so run this periodically (a cron or a
// background ticker). It is safe to run concurrently with live traffic and on several replicas at
// once: it only touches rows already past their expiry.
func (s *ChallengeStore) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM passkey_challenges WHERE expires_at <= now()`)
	if err != nil {
		return 0, errors.Join(errors.New("pgx passkey: prune expired ceremony challenges"), err)
	}
	return tag.RowsAffected(), nil
}

var _ passkey.ChallengeStore = (*ChallengeStore)(nil)
