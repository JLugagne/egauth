package identity

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	contract "github.com/JLugagne/egauth/store/identity"
)

var errReservedProvider = errors.New(`identity: federated provider "password" is reserved for the password credential`)

func reserved(m contract.Mutation) error {
	provider := ""
	switch x := m.(type) {
	case contract.LinkFederated:
		provider = x.Identity.Provider
	case contract.CreateVerified:
		provider = x.Federated.Provider
	case contract.UnlinkFederated:
		provider = x.Provider
	}
	if provider == passwordProvider {
		return errors.Join(contract.ErrInvalidMutation, errReservedProvider)
	}
	return nil
}

func (s *Store) Apply(ctx context.Context, m contract.Mutation) (contract.Applied, error) {
	if err := contract.Validate(m); err != nil {
		return contract.Applied{}, err
	}
	if err := reserved(m); err != nil {
		return contract.Applied{}, err
	}
	var out contract.Applied
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = apply(ctx, tx, m)
		return err
	})
	if err != nil {
		return contract.Applied{}, err
	}
	return out, nil
}

type current struct {
	sub      principal.Subject
	email    contract.Identifier
	verified bool
	phone    contract.Identifier
	recovery contract.Identifier
	epoch    uint64
}

func subjectOf(m contract.Mutation) principal.Subject {
	switch x := m.(type) {
	case contract.SetPassword:
		return x.Subject
	case contract.MarkEmailVerified:
		return x.Subject
	case contract.ChangeEmail:
		return x.Subject
	case contract.SetPhone:
		return x.Subject
	case contract.SetRecoveryEmail:
		return x.Subject
	case contract.SetDisabledState:
		return x.Subject
	case contract.SetMustChange:
		return x.Subject
	case contract.Tombstone:
		return x.Subject
	case contract.BumpEpoch:
		return x.Subject
	case contract.LinkFederated:
		return x.Subject
	case contract.UnlinkFederated:
		return x.Subject
	}
	return principal.Subject{}
}

func lockUser(ctx context.Context, tx pgx.Tx, sub principal.Subject) (current, error) {
	var (
		email           string
		phone, recovery *string
		verified, del   *time.Time
		epoch           int64
	)
	err := tx.QueryRow(ctx, `SELECT email, email_verified_at, phone, recovery_email, deleted_at, security_epoch
FROM users WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, sub.User, sub.Tenant.String()).
		Scan(&email, &verified, &phone, &recovery, &del, &epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return current{}, store.ErrNotFound
	}
	if err != nil {
		return current{}, errors.Join(errors.New("identity: lock user"), err)
	}
	if del != nil {
		return current{}, contract.ErrTombstoned
	}
	c := current{sub: sub, verified: verified != nil, epoch: uint64(max(epoch, 0))}
	c.email = ident(contract.IdentifierEmail, &email)
	c.phone = ident(contract.IdentifierPhone, phone)
	c.recovery = ident(contract.IdentifierRecoveryEmail, recovery)
	return c, nil
}

func apply(ctx context.Context, tx pgx.Tx, m contract.Mutation) (contract.Applied, error) {
	var (
		c   current
		old contract.Identifier
		err error
	)
	if cv, ok := m.(contract.CreateVerified); ok {
		if c, err = create(ctx, tx, cv); err != nil {
			return contract.Applied{}, err
		}
	} else {
		if c, err = lockUser(ctx, tx, subjectOf(m)); err != nil {
			return contract.Applied{}, err
		}
		if old, err = mutate(ctx, tx, c, m); err != nil {
			return contract.Applied{}, err
		}
	}
	return effects(ctx, tx, c, m, old)
}

func exec(ctx context.Context, tx migrate.Querier, what string, sql string, args ...any) (int64, error) {
	tag, err := tx.Exec(ctx, sql, args...)
	if isUnique(err) {
		return 0, contract.ErrIdentifierTaken
	}
	if err != nil {
		return 0, errors.Join(errors.New("identity: "+what), err)
	}
	return tag.RowsAffected(), nil
}

func mutate(ctx context.Context, tx pgx.Tx, c current, m contract.Mutation) (contract.Identifier, error) {
	id, tenant := c.sub.User, c.sub.Tenant.String()
	var err error
	switch x := m.(type) {
	case contract.SetPassword:
		err = setPassword(ctx, tx, c.sub, x.PHC, x.Reason.ForcesChange())
	case contract.MarkEmailVerified:
		if c.verified {
			return contract.Identifier{}, errors.Join(store.ErrConflict, errors.New("identity: email is already verified"))
		}
		if _, err = exec(ctx, tx, "verify email", `UPDATE users SET email_verified_at = now(), updated_at = now()
WHERE id = $1 AND tenant_id = $2`, id, tenant); err != nil {
			return contract.Identifier{}, err
		}
		if _, err = exec(ctx, tx, "wipe pre-verification credentials", `DELETE FROM identities
WHERE user_id = $1 AND tenant_id = $2`, id, tenant); err != nil {
			return contract.Identifier{}, err
		}
		if !x.PHC.IsZero() {
			err = setPassword(ctx, tx, c.sub, x.PHC, false)
		}
	case contract.ChangeEmail:
		_, err = exec(ctx, tx, "change email", `UPDATE users SET email = $3, email_verified_at = now(), updated_at = now()
WHERE id = $1 AND tenant_id = $2`, id, tenant, x.Email.Value())
		return c.email, err
	case contract.SetPhone:
		_, err = exec(ctx, tx, "set phone", `UPDATE users
SET phone = $3, phone_verified_at = CASE WHEN $3::varchar IS NULL THEN NULL ELSE now() END, updated_at = now()
WHERE id = $1 AND tenant_id = $2`, id, tenant, nullIdent(x.Phone))
		return c.phone, err
	case contract.SetRecoveryEmail:
		_, err = exec(ctx, tx, "set recovery email", `UPDATE users
SET recovery_email = $3, recovery_email_verified_at = CASE WHEN $3::varchar IS NULL THEN NULL ELSE now() END, updated_at = now()
WHERE id = $1 AND tenant_id = $2`, id, tenant, nullIdent(x.RecoveryEmail))
		return c.recovery, err
	case contract.SetDisabledState:
		q := `UPDATE users SET disabled_at = NULL, updated_at = now() WHERE id = $1 AND tenant_id = $2`
		if x.Disable {
			q = `UPDATE users SET disabled_at = coalesce(disabled_at, now()), updated_at = now() WHERE id = $1 AND tenant_id = $2`
		}
		_, err = exec(ctx, tx, "set disabled state", q, id, tenant)
	case contract.SetMustChange:
		var n int64
		n, err = exec(ctx, tx, "set must change", `UPDATE identities SET must_change_password = $3
WHERE user_id = $1 AND tenant_id = $2 AND provider = 'password'`, id, tenant, x.MustChange)
		if err == nil && n == 0 && x.MustChange {
			err = errors.Join(contract.ErrInvalidMutation, errors.New("must change requires a password"))
		}
	case contract.Tombstone:
		_, err = exec(ctx, tx, "tombstone", `UPDATE users SET deleted_at = now(), updated_at = now()
WHERE id = $1 AND tenant_id = $2`, id, tenant)
	case contract.LinkFederated:
		err = link(ctx, tx, c.sub, x.Identity)
	case contract.UnlinkFederated:
		var n int64
		n, err = exec(ctx, tx, "unlink", `DELETE FROM identities
WHERE user_id = $1 AND tenant_id = $2 AND provider = $3 AND provider_id = $4 AND provider <> 'password'`,
			id, tenant, x.Provider, x.ProviderSubject)
		if err == nil && n == 0 {
			err = store.ErrNotFound
		}
	}
	return contract.Identifier{}, err
}

func setPassword(ctx context.Context, tx pgx.Tx, sub principal.Subject, phc contract.PasswordHash, mustChange bool) error {
	n, err := exec(ctx, tx, "set password", `UPDATE identities
SET password_hash = $3, failed_attempts = 0, locked_until = NULL, password_changed_at = now(),
    must_change_password = $4, updated_at = now()
WHERE user_id = $1 AND tenant_id = $2 AND provider = 'password'`, sub.User, sub.Tenant.String(), phc.PHC(), mustChange)
	if err != nil || n > 0 {
		return err
	}
	rowID, err := uuid.NewV7()
	if err != nil {
		return errors.Join(errors.New("identity: credential id"), err)
	}
	_, err = exec(ctx, tx, "insert password", `INSERT INTO identities
    (id, user_id, tenant_id, provider, provider_id, password_hash, password_changed_at, must_change_password, created_at, updated_at)
VALUES ($1, $2, $3, 'password', $4, $5, now(), $6, now(), now())`,
		rowID, sub.User, sub.Tenant.String(), sub.User.String(), phc.PHC(), mustChange)
	return err
}

func link(ctx context.Context, tx pgx.Tx, sub principal.Subject, f contract.FederatedIdentity) error {
	var (
		rowID, owner uuid.UUID
		authority    string
		tombstoned   bool
	)
	err := tx.QueryRow(ctx, `SELECT i.id, i.user_id, i.authority, u.deleted_at IS NOT NULL
FROM identities i LEFT JOIN users u ON u.id = i.user_id AND u.tenant_id = i.tenant_id
WHERE i.tenant_id = $1 AND i.provider = $2 AND i.provider_id = $3
FOR UPDATE OF i`, sub.Tenant.String(), f.Provider, f.ProviderSubject).Scan(&rowID, &owner, &authority, &tombstoned)
	switch {
	case err == nil && owner == sub.User && authority == f.Authority:
		return errors.Join(store.ErrConflict, errors.New("identity: provider account already linked to this subject"))
	case err == nil && owner == sub.User:
		_, err = exec(ctx, tx, "rebind link", `UPDATE identities
SET authority = $2, provider_email = $3, provider_email_verified = $4, created_at = now(), updated_at = now()
WHERE id = $1`, rowID, f.Authority, nullIdent(f.ProviderEmail), f.ProviderEmailVerified)
		return err
	case err == nil && !tombstoned:
		return contract.ErrIdentifierTaken
	case err == nil:
		if _, err := exec(ctx, tx, "release tombstoned link", `DELETE FROM identities WHERE id = $1`, rowID); err != nil {
			return err
		}
	case !errors.Is(err, pgx.ErrNoRows):
		return errors.Join(errors.New("identity: read federated link"), err)
	}
	rowID, err = uuid.NewV7()
	if err != nil {
		return errors.Join(errors.New("identity: link id"), err)
	}
	_, err = exec(ctx, tx, "link", `INSERT INTO identities
    (id, user_id, tenant_id, provider, provider_id, authority, provider_email, provider_email_verified, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())`,
		rowID, sub.User, sub.Tenant.String(), f.Provider, f.ProviderSubject, f.Authority, nullIdent(f.ProviderEmail), f.ProviderEmailVerified)
	return err
}

func create(ctx context.Context, tx pgx.Tx, m contract.CreateVerified) (current, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return current{}, errors.Join(errors.New("identity: user id"), err)
	}
	c := current{sub: principal.Subject{Tenant: m.Tenant, User: id}, email: m.Email, verified: true}
	if _, err := exec(ctx, tx, "create user", `INSERT INTO users
    (id, tenant_id, email, email_verified_at, security_epoch, identifier_state, created_at, updated_at)
VALUES ($1, $2, $3, now(), 0, $4, now(), now())`, id, m.Tenant.String(), m.Email.Value(), int16(contract.IdentifiersCanonical)); err != nil {
		return current{}, err
	}
	if !m.PHC.IsZero() {
		if err := setPassword(ctx, tx, c.sub, m.PHC, m.MustChange); err != nil {
			return current{}, err
		}
	}
	if m.Federated != (contract.FederatedIdentity{}) {
		if err := link(ctx, tx, c.sub, m.Federated); err != nil {
			return current{}, err
		}
	}
	return c, nil
}

func effects(ctx context.Context, tx pgx.Tx, c current, m contract.Mutation, old contract.Identifier) (contract.Applied, error) {
	fx := contract.EffectsOf(m)
	epoch := c.epoch
	if fx.BumpsEpoch {
		var e int64
		if err := tx.QueryRow(ctx, `UPDATE users SET security_epoch = security_epoch + 1
WHERE id = $1 AND tenant_id = $2 RETURNING security_epoch`, c.sub.User, c.sub.Tenant.String()).Scan(&e); err != nil {
			return contract.Applied{}, errors.Join(errors.New("identity: bump epoch"), err)
		}
		epoch = uint64(max(e, 0))
	}
	items := contract.OutboxFor(m, c.sub, old)
	for i := range items {
		if err := insertOutbox(ctx, tx, &items[i]); err != nil {
			return contract.Applied{}, err
		}
	}
	if fx.BumpsEpoch {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, epochLogLock); err != nil {
			return contract.Applied{}, errors.Join(errors.New("identity: lock epoch log"), err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO egauth_epoch_log (tenant_id, user_id, epoch, reason, created_at)
VALUES ($1, $2, $3, $4, now())`, c.sub.Tenant.String(), c.sub.User, int64(epoch), int16(fx.Event)); err != nil {
			return contract.Applied{}, errors.Join(errors.New("identity: append epoch log"), err)
		}
	}
	return contract.Applied{Subject: c.sub, NewEpoch: epoch, Outbox: items}, nil
}
