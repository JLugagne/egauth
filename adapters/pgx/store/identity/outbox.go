package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JLugagne/egauth/store"
	contract "github.com/JLugagne/egauth/store/identity"
)

type payload struct {
	Keep       uuid.UUID `json:"keep"`
	Rotation   uint8     `json:"rotation,omitempty"`
	Change     uint8     `json:"change,omitempty"`
	Identifier uint8     `json:"identifier,omitempty"`
	OldKind    uint8     `json:"old_kind,omitempty"`
	Old        string    `json:"old,omitempty"`
}

func encodePayload(it contract.OutboxItem) ([]byte, error) {
	p := payload{
		Keep: it.Keep, Rotation: uint8(it.Rotation), Change: uint8(it.Change), Identifier: uint8(it.Identifier),
		OldKind: uint8(it.Old.Kind()), Old: it.Old.Value(),
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, errors.Join(errors.New("identity: encode outbox payload"), err)
	}
	return b, nil
}

func decodePayload(b []byte, it *contract.OutboxItem) error {
	var p payload
	if err := json.Unmarshal(b, &p); err != nil {
		return errors.Join(errors.New("identity: decode outbox payload"), err)
	}
	it.Keep = p.Keep
	it.Rotation = contract.RotationReason(p.Rotation)
	it.Change = contract.FactorChange(p.Change)
	it.Identifier = contract.IdentifierKind(p.Identifier)
	if p.OldKind == 0 {
		return nil
	}
	old, err := contract.NewIdentifier(contract.IdentifierKind(p.OldKind), p.Old)
	if err != nil {
		return errors.Join(errors.New("identity: decode outbox payload"), err)
	}
	it.Old = old
	return nil
}

func insertOutbox(ctx context.Context, tx pgx.Tx, it *contract.OutboxItem) error {
	body, err := encodePayload(*it)
	if err != nil {
		return err
	}
	err = tx.QueryRow(ctx, `INSERT INTO egauth_lifecycle_outbox
    (tenant_id, user_id, event, payload, subscriber, attempts, next_attempt_at, created_at)
VALUES ($1, $2, $3, $4, $5, 0, now(), now())
RETURNING id, next_attempt_at, created_at`,
		it.Subject.Tenant.String(), it.Subject.User, int16(it.Event), body, it.Component.String()).
		Scan(&it.ID, &it.NextAttemptAt, &it.CreatedAt)
	if err != nil {
		return errors.Join(errors.New("identity: write outbox"), err)
	}
	it.NextAttemptAt, it.CreatedAt = it.NextAttemptAt.UTC(), it.CreatedAt.UTC()
	return nil
}

// PendingOutbox skips the rows this build cannot decode (a component or an event added by a newer
// release, an unparsable tenant or payload) and leaves them pending for a replica that can, so one
// such row never stalls the dispatcher. The rows it returns stay oldest first.
func (s *Store) PendingOutbox(ctx context.Context, limit int) ([]contract.OutboxItem, error) {
	var out []contract.OutboxItem
	after := int64(0)
	for len(out) < limit {
		want := limit - len(out)
		page, last, scanned, err := s.pendingPage(ctx, after, want)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if scanned < want {
			break
		}
		after = last
	}
	return out, nil
}

func knownSubscribers() []string {
	var out []string
	for _, c := range contract.Components() {
		out = append(out, c.String())
	}
	return out
}

func knownEvents() []int16 {
	var out []int16
	for e := contract.EventCredentialRotated; e.Valid(); e++ {
		out = append(out, int16(e))
	}
	return out
}

func (s *Store) pendingPage(ctx context.Context, after int64, limit int) ([]contract.OutboxItem, int64, int, error) {
	rows, err := s.db.Query(ctx, `SELECT id, tenant_id, user_id, event, payload, subscriber, attempts, next_attempt_at, created_at
FROM egauth_lifecycle_outbox
WHERE done_at IS NULL AND next_attempt_at <= now() AND id > $1 AND subscriber = ANY($2) AND event = ANY($3)
ORDER BY id LIMIT $4`, after, knownSubscribers(), knownEvents(), limit)
	if err != nil {
		return nil, 0, 0, errors.Join(errors.New("identity: read outbox"), err)
	}
	defer rows.Close()
	var (
		out     []contract.OutboxItem
		last    int64
		scanned int
	)
	for rows.Next() {
		var (
			it         contract.OutboxItem
			tenant     string
			subscriber string
			event      int16
			body       []byte
		)
		if err := rows.Scan(&it.ID, &tenant, &it.Subject.User, &event, &body, &subscriber, &it.Attempts, &it.NextAttemptAt, &it.CreatedAt); err != nil {
			return nil, 0, 0, errors.Join(errors.New("identity: read outbox"), err)
		}
		scanned++
		last = it.ID
		if decodeItem(&it, tenant, subscriber, event, body) != nil {
			continue
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, errors.Join(errors.New("identity: read outbox"), err)
	}
	return out, last, scanned, nil
}

func decodeItem(it *contract.OutboxItem, tenant, subscriber string, event int16, body []byte) error {
	var err error
	if it.Subject.Tenant, err = tenantOf(tenant); err != nil {
		return err
	}
	if it.Component, err = contract.ParseComponent(subscriber); err != nil {
		return err
	}
	if it.Event = contract.Event(event); !it.Event.Valid() {
		return errors.New("identity: stored outbox event is not declared")
	}
	if err := decodePayload(body, it); err != nil {
		return err
	}
	it.NextAttemptAt, it.CreatedAt = it.NextAttemptAt.UTC(), it.CreatedAt.UTC()
	return nil
}

func (s *Store) AckOutbox(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `UPDATE egauth_lifecycle_outbox SET done_at = coalesce(done_at, now()) WHERE id = $1`, id)
	if err != nil {
		return errors.Join(errors.New("identity: ack outbox"), err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) FailOutbox(ctx context.Context, id int64, next time.Time) error {
	var found bool
	err := s.db.QueryRow(ctx, `WITH failed AS (
    UPDATE egauth_lifecycle_outbox SET attempts = attempts + 1, next_attempt_at = $2
    WHERE id = $1 AND done_at IS NULL
    RETURNING id)
SELECT EXISTS (SELECT 1 FROM failed) OR EXISTS (SELECT 1 FROM egauth_lifecycle_outbox WHERE id = $1)`, id, next).Scan(&found)
	if err != nil {
		return errors.Join(errors.New("identity: fail outbox"), err)
	}
	if !found {
		return store.ErrNotFound
	}
	return nil
}
