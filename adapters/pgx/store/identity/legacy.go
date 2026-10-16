package identity

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/principal"
	contract "github.com/JLugagne/egauth/store/identity"
)

func (s *Store) V016Identifiers(ctx context.Context, after principal.Subject, limit int) ([]contract.V016Identifiers, error) {
	if limit < 1 {
		return nil, errors.Join(contract.ErrInvalidMutation, errors.New("limit must be positive"))
	}
	rows, err := s.db.Query(ctx, `SELECT tenant_id, id, email, coalesce(phone, ''), coalesce(recovery_email, ''),
    deleted_at IS NOT NULL, identifier_state
FROM users WHERE identifier_state <> $1 AND (tenant_id, id) > ($2, $3)
ORDER BY tenant_id, id LIMIT $4`, int16(contract.IdentifiersCanonical), after.Tenant.String(), after.User, limit)
	if err != nil {
		return nil, errors.Join(errors.New("identity: list legacy identifiers"), err)
	}
	defer rows.Close()
	out := []contract.V016Identifiers{}
	for rows.Next() {
		var (
			r      contract.V016Identifiers
			tenant string
			user   uuid.UUID
			state  int16
		)
		if err := rows.Scan(&tenant, &user, &r.Email, &r.Phone, &r.RecoveryEmail, &r.Tombstoned, &state); err != nil {
			return nil, errors.Join(errors.New("identity: list legacy identifiers"), err)
		}
		if r.Subject.Tenant, err = tenantOf(tenant); err != nil {
			return nil, err
		}
		r.Subject.User, r.State = user, contract.IdentifierState(max(state, 0))
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(errors.New("identity: list legacy identifiers"), err)
	}
	return out, nil
}

func (s *Store) CountLegacyIdentifiers(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM users WHERE identifier_state = $1`,
		int16(contract.IdentifiersUnchecked)).Scan(&n); err != nil {
		return 0, errors.Join(errors.New("identity: count legacy identifiers"), err)
	}
	return n, nil
}

func (s *Store) UpgradeIdentifiers(ctx context.Context, u contract.IdentifierUpgrade) (bool, error) {
	if err := contract.ValidateUpgrade(u); err != nil {
		return false, err
	}
	o := u.Old
	n, err := exec(ctx, s.db, "upgrade identifiers", `UPDATE users SET
    email = CASE WHEN $3 THEN $4 ELSE email END,
    phone = CASE WHEN $5 THEN $6 ELSE phone END,
    recovery_email = CASE WHEN $7 THEN $8 ELSE recovery_email END,
    identifier_state = $9
WHERE id = $1 AND tenant_id = $2 AND identifier_state <> $10
  AND email = $11 AND coalesce(phone, '') = $12 AND coalesce(recovery_email, '') = $13`,
		o.Subject.User, o.Subject.Tenant.String(),
		u.Email != nil, value(u.Email), u.Phone != nil, value(u.Phone), u.RecoveryEmail != nil, value(u.RecoveryEmail),
		int16(u.State), int16(contract.IdentifiersCanonical), o.Email, o.Phone, o.RecoveryEmail)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func value(id *contract.Identifier) string {
	if id == nil {
		return ""
	}
	return id.Value()
}
