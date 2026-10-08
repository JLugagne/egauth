// Package federation is the PostgreSQL federation.Store. Provider specs live in the v0.16
// oauth_oidc_providers table, extended in place by 002_kek_v1.sql, with the sealed client secret kept
// base64-encoded and the scopes space-separated as v0.16 wrote them. Linked identities are read from
// the identity module's identities table, so that module must be migrated too.
package federation

import (
	"context"
	"embed"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	identitystore "github.com/JLugagne/egauth/adapters/pgx/store/identity"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	contract "github.com/JLugagne/egauth/store/federation"
)

// Migrations holds the schema of the store; pgxstore registers it as module "federation". File 001
// is the v0.16 oauth file under its v0.16 name, so a v0.16 database skips it.
//
// Beyond the DESIGN section 4.9 list, 002 adds user_info_url, which Provider.UserInfoURL needs, and a
// unique seq identity, the stable cursor of V016Sealed. Both are expand-only and idempotent.
//
//go:embed migrations/*.sql
var Migrations embed.FS

var _ contract.Store = (*Store)(nil)

const (
	moduleName       = "federation"
	passwordProvider = "password"
	specColumns      = `tenant_id, provider_name, client_id, client_secret, aad_version, auth_url, token_url,
    user_info_url, scopes, issuer, jwks_url, domains, email_verification, updated_at`
	linkColumns = `i.user_id, i.tenant_id, i.provider, i.provider_id, i.provider_email, i.provider_email_verified, i.created_at`
)

var (
	errInvalidSpec  = errors.New("federation: invalid provider spec")
	errInvalidLimit = errors.New("federation: limit must be positive")
	errInvalidSeal  = errors.New("federation: invalid reseal")
)

// Store is safe for concurrent use. Update stamps come from the database clock. Links of a tombstoned
// account are never returned, and Ping fails until the identity module is migrated too.
type Store struct {
	db migrate.DB
}

// New returns a store over db, typically a *pgxpool.Pool, whose schema Migrate has created for this
// module and for the identity module.
func New(db migrate.DB) *Store { return &Store{db: db} }

func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return errors.Join(errors.New("federation: ping"), err)
	}
	if err := migrate.Check(ctx, s.db, "identity", identitystore.Migrations); err != nil {
		return errors.Join(errors.New("federation: links are read from the identity module's tables"), err)
	}
	return migrate.Check(ctx, s.db, moduleName, Migrations)
}

func (s *Store) Durability() store.Durability { return store.Shared }

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return errors.Join(errors.New("federation: begin"), err)
	}
	for _, q := range []string{
		`DELETE FROM oauth_oidc_providers WHERE tenant_id = $1`,
		`DELETE FROM identities WHERE tenant_id = $1 AND provider <> 'password'`,
	} {
		if _, err := tx.Exec(ctx, q, t.String()); err != nil {
			return errors.Join(errors.New("federation: erase tenant"), err, rollback(ctx, tx))
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(errors.New("federation: commit"), err)
	}
	return nil
}

func rollback(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Rollback(context.WithoutCancel(ctx)); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

func checkSpec(p contract.ProviderSpec) error {
	if p.AADVersion != contract.AADVersionCurrent {
		return contract.ErrLegacyAADVersion
	}
	if p.Name == "" || len(p.SealedSecret) == 0 || !p.EmailVerification.Valid() {
		return errInvalidSpec
	}
	for _, sc := range p.Scopes {
		if sc == "" || strings.ContainsAny(sc, " \t\r\n") {
			return errInvalidSpec
		}
	}
	return nil
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func nilIfEmpty(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return in
}

func (s *Store) PutProvider(ctx context.Context, p contract.ProviderSpec) error {
	if err := checkSpec(p); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `INSERT INTO oauth_oidc_providers
    (tenant_id, provider_name, client_id, client_secret, aad_version, auth_url, token_url, user_info_url,
     scopes, issuer, jwks_url, domains, email_verification, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now(), now())
ON CONFLICT (tenant_id, provider_name) DO UPDATE SET
    client_id = EXCLUDED.client_id, client_secret = EXCLUDED.client_secret, aad_version = EXCLUDED.aad_version,
    auth_url = EXCLUDED.auth_url, token_url = EXCLUDED.token_url, user_info_url = EXCLUDED.user_info_url,
    scopes = EXCLUDED.scopes, issuer = EXCLUDED.issuer, jwks_url = EXCLUDED.jwks_url, domains = EXCLUDED.domains,
    email_verification = EXCLUDED.email_verification, updated_at = now()`,
		p.Tenant.String(), p.Name, p.ClientID, base64.StdEncoding.EncodeToString(p.SealedSecret), int16(p.AADVersion),
		p.AuthURL, p.TokenURL, p.UserInfoURL, strings.Join(p.Scopes, " "), p.Issuer, p.JWKSURL,
		nonNil(p.Domains), int16(p.EmailVerification))
	if err != nil {
		return errors.Join(errors.New("federation: put provider"), err)
	}
	return nil
}

func tenantOf(s string) (principal.TenantID, error) {
	if s == "" {
		return principal.TenantID{}, nil
	}
	t, err := principal.ParseTenantID(s)
	if err != nil {
		return principal.TenantID{}, errors.Join(errors.New("federation: stored tenant"), err)
	}
	return t, nil
}

func smallUint(v int16, what string) (uint8, error) {
	if v < 0 || v > 255 {
		return 0, errors.New("federation: stored " + what + " out of range")
	}
	return uint8(v), nil
}

func scanSpec(row pgx.Row) (contract.ProviderSpec, error) {
	var (
		p                    contract.ProviderSpec
		tenant, sealed, scps string
		aad, verification    int16
	)
	if err := row.Scan(&tenant, &p.Name, &p.ClientID, &sealed, &aad, &p.AuthURL, &p.TokenURL, &p.UserInfoURL,
		&scps, &p.Issuer, &p.JWKSURL, &p.Domains, &verification, &p.UpdatedAt); err != nil {
		return contract.ProviderSpec{}, err
	}
	var err error
	if p.Tenant, err = tenantOf(tenant); err != nil {
		return contract.ProviderSpec{}, err
	}
	if p.SealedSecret, err = base64.StdEncoding.DecodeString(sealed); err != nil {
		return contract.ProviderSpec{}, errors.Join(errors.New("federation: stored client secret is not base64"), err)
	}
	if p.AADVersion, err = smallUint(aad, "aad_version"); err != nil {
		return contract.ProviderSpec{}, err
	}
	v, err := smallUint(verification, "email_verification")
	if err != nil {
		return contract.ProviderSpec{}, err
	}
	p.EmailVerification = contract.EmailVerification(v)
	if !p.EmailVerification.Valid() {
		return contract.ProviderSpec{}, errors.New("federation: stored email_verification is not a declared value")
	}
	p.Scopes = nilIfEmpty(strings.Fields(scps))
	p.Domains = nilIfEmpty(p.Domains)
	p.UpdatedAt = p.UpdatedAt.UTC()
	return p, nil
}

func (s *Store) GetProvider(ctx context.Context, t principal.TenantID, name string) (contract.ProviderSpec, error) {
	p, err := scanSpec(s.db.QueryRow(ctx, `SELECT `+specColumns+` FROM oauth_oidc_providers
WHERE tenant_id = $1 AND provider_name = $2`, t.String(), name))
	if errors.Is(err, pgx.ErrNoRows) {
		return contract.ProviderSpec{}, store.ErrNotFound
	}
	if err != nil {
		return contract.ProviderSpec{}, errors.Join(errors.New("federation: get provider"), err)
	}
	return p, nil
}

func (s *Store) ListProviders(ctx context.Context, t principal.TenantID) ([]contract.ProviderSpec, error) {
	rows, err := s.db.Query(ctx, `SELECT `+specColumns+` FROM oauth_oidc_providers
WHERE tenant_id = $1 ORDER BY provider_name COLLATE "C"`, t.String())
	if err != nil {
		return nil, errors.Join(errors.New("federation: list providers"), err)
	}
	defer rows.Close()
	out := []contract.ProviderSpec{}
	for rows.Next() {
		p, err := scanSpec(rows)
		if err != nil {
			return nil, errors.Join(errors.New("federation: list providers"), err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(errors.New("federation: list providers"), err)
	}
	return out, nil
}

func (s *Store) DeleteProvider(ctx context.Context, t principal.TenantID, name string) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM oauth_oidc_providers WHERE tenant_id = $1 AND provider_name = $2`, t.String(), name); err != nil {
		return errors.Join(errors.New("federation: delete provider"), err)
	}
	return nil
}

func scanLink(row pgx.Row) (contract.LinkedIdentity, error) {
	var (
		l        contract.LinkedIdentity
		tenant   string
		email    *string
		verified bool
		linked   time.Time
	)
	if err := row.Scan(&l.Subject.User, &tenant, &l.Key.Provider, &l.Key.ProviderSubject, &email, &verified, &linked); err != nil {
		return contract.LinkedIdentity{}, err
	}
	var err error
	if l.Subject.Tenant, err = tenantOf(tenant); err != nil {
		return contract.LinkedIdentity{}, err
	}
	if email != nil {
		l.ProviderEmail = *email
	}
	l.ProviderEmailVerified = verified && l.ProviderEmail != ""
	l.LinkedAt = linked.UTC()
	return l, nil
}

func (s *Store) FindLinked(ctx context.Context, t principal.TenantID, k contract.LinkKey) (contract.LinkedIdentity, error) {
	if k.Provider == passwordProvider {
		return contract.LinkedIdentity{}, store.ErrNotFound
	}
	l, err := scanLink(s.db.QueryRow(ctx, `SELECT `+linkColumns+`
FROM identities i JOIN users u ON u.id = i.user_id AND u.tenant_id = i.tenant_id
WHERE i.tenant_id = $1 AND i.provider = $2 AND i.provider_id = $3 AND u.deleted_at IS NULL`,
		t.String(), k.Provider, k.ProviderSubject))
	if errors.Is(err, pgx.ErrNoRows) {
		return contract.LinkedIdentity{}, store.ErrNotFound
	}
	if err != nil {
		return contract.LinkedIdentity{}, errors.Join(errors.New("federation: find linked identity"), err)
	}
	return l, nil
}

func (s *Store) LinkedFor(ctx context.Context, sub principal.Subject) ([]contract.LinkedIdentity, error) {
	rows, err := s.db.Query(ctx, `SELECT `+linkColumns+`
FROM identities i JOIN users u ON u.id = i.user_id AND u.tenant_id = i.tenant_id
WHERE i.user_id = $1 AND i.tenant_id = $2 AND i.provider <> 'password' AND u.deleted_at IS NULL
ORDER BY i.created_at, i.provider COLLATE "C", i.provider_id COLLATE "C"`, sub.User, sub.Tenant.String())
	if err != nil {
		return nil, errors.Join(errors.New("federation: list linked identities"), err)
	}
	defer rows.Close()
	out := []contract.LinkedIdentity{}
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, errors.Join(errors.New("federation: list linked identities"), err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(errors.New("federation: list linked identities"), err)
	}
	return out, nil
}

func (s *Store) DeleteForSubject(ctx context.Context, sub principal.Subject) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM identities WHERE user_id = $1 AND tenant_id = $2 AND provider <> 'password'`,
		sub.User, sub.Tenant.String()); err != nil {
		return errors.Join(errors.New("federation: delete linked identities"), err)
	}
	return nil
}

func (s *Store) CountLegacySealed(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM oauth_oidc_providers WHERE aad_version = $1`,
		int16(contract.AADVersionLegacy)).Scan(&n); err != nil {
		return 0, errors.Join(errors.New("federation: count legacy secrets"), err)
	}
	return n, nil
}

func (s *Store) V016Sealed(ctx context.Context, after store.Cursor, limit int) ([]contract.V016Row, store.Cursor, error) {
	if limit < 1 {
		return nil, after, errInvalidLimit
	}
	if after.Position() > uint64(1<<63-1) {
		return []contract.V016Row{}, after, nil
	}
	rows, err := s.db.Query(ctx, `SELECT seq, tenant_id, provider_name, client_secret FROM oauth_oidc_providers
WHERE aad_version = $1 AND seq > $2 ORDER BY seq LIMIT $3`, int16(contract.AADVersionLegacy), int64(after.Position()), limit)
	if err != nil {
		return nil, after, errors.Join(errors.New("federation: list legacy secrets"), err)
	}
	defer rows.Close()
	out := []contract.V016Row{}
	last := after.Position()
	for rows.Next() {
		var (
			seq            int64
			tenant, sealed string
			r              contract.V016Row
		)
		if err := rows.Scan(&seq, &tenant, &r.Ref.Provider, &sealed); err != nil {
			return nil, after, errors.Join(errors.New("federation: list legacy secrets"), err)
		}
		if r.Ref.Tenant, err = tenantOf(tenant); err != nil {
			return nil, after, err
		}
		if r.Sealed, err = base64.StdEncoding.DecodeString(sealed); err != nil {
			return nil, after, errors.Join(errors.New("federation: stored client secret is not base64"), err)
		}
		out = append(out, r)
		last = uint64(max(seq, 0))
	}
	if err := rows.Err(); err != nil {
		return nil, after, errors.Join(errors.New("federation: list legacy secrets"), err)
	}
	return out, store.RestoreCursor(last), nil
}

func (s *Store) ReplaceSealed(ctx context.Context, r contract.Reseal) (bool, error) {
	if len(r.Old) == 0 || len(r.New) == 0 || r.Ref.Provider == "" {
		return false, errInvalidSeal
	}
	tag, err := s.db.Exec(ctx, `UPDATE oauth_oidc_providers SET client_secret = $3, aad_version = $5
WHERE tenant_id = $1 AND provider_name = $2 AND client_secret = $4`,
		r.Ref.Tenant.String(), r.Ref.Provider, base64.StdEncoding.EncodeToString(r.New),
		base64.StdEncoding.EncodeToString(r.Old), int16(contract.AADVersionCurrent))
	if err != nil {
		return false, errors.Join(errors.New("federation: replace sealed secret"), err)
	}
	return tag.RowsAffected() == 1, nil
}
