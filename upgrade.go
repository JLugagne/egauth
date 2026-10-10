package egauth

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	fedstore "github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/mfa"
)

const upgradePageSize = 100

// ErrUpgradeIncomplete is returned by UpgradeSecretsV016, with the report, when a v0.16 row opens
// under no candidate associated data and so stays in place. New refuses to start until the row is
// repaired or deleted.
var ErrUpgradeIncomplete = errors.New("egauth: v0.16 secrets remain that no legacy associated data opens")

// UpgradeRow names a v0.16 row without any secret material. Kind is the v0.16 table; ID is the user
// id, the provider name or the key id, and Tenant is the zero TenantID for a single-tenant row.
type UpgradeRow struct {
	Kind   string
	Tenant principal.TenantID
	ID     string
}

// UpgradeReport is the outcome of one UpgradeSecretsV016 run. Upgraded counts the rows this run
// re-sealed; Concurrent counts rows another instance re-sealed or replaced first; Unopenable lists
// every row that no candidate opens.
type UpgradeReport struct {
	Upgraded   int
	Concurrent int
	Unopenable []UpgradeRow
}

type legacyRow struct {
	row     UpgradeRow
	ref     func() (sealing.Ref, error)
	sealed  []byte
	replace func(ctx context.Context, sealed []byte) (bool, error)
}

type legacySource struct {
	page func(ctx context.Context, after store.Cursor) ([]legacyRow, store.Cursor, error)
}

// UpgradeSecretsV016 re-seals every v0.16 TOTP secret, OAuth client secret and tenant signing key
// under the v0.17 format, trying each row's legacy associated data (tenant and owner, then tenant
// alone for signing keys, then none) and writing back through the store's ReplaceSealed
// compare-and-swap. It is idempotent and safe to run concurrently from several instances: a row another
// instance changed first is counted as Concurrent and never overwritten. Stores absent from s (Federation, Keys) are skipped. A row
// that opens under no candidate is listed in the report and makes it return ErrUpgradeIncomplete
// after every other row was handled. A store failure, a cancelled ctx, a KEK failure or a
// LegacyOpener error other than kek.ErrOpenFailed and kek.ErrMalformed stops the run and returns it.
// Run it once at startup, before New.
func UpgradeSecretsV016(ctx context.Context, s Storage, legacy kek.LegacyOpener, k kek.KEK) (UpgradeReport, error) {
	var rep UpgradeReport
	if !present(s.MFA) || !present(legacy) || !present(k) {
		return rep, errors.New("egauth: UpgradeSecretsV016 needs Storage.MFA, a LegacyOpener and a KEK")
	}
	sources := []legacySource{mfaSource(s.MFA)}
	if present(s.Federation) {
		sources = append(sources, federationSource(s.Federation))
	}
	if present(s.Keys) {
		sources = append(sources, keysSource(s.Keys))
	}
	for _, src := range sources {
		if err := src.run(ctx, legacy, k, &rep); err != nil {
			return rep, err
		}
	}
	if len(rep.Unopenable) > 0 {
		return rep, ErrUpgradeIncomplete
	}
	return rep, nil
}

func (src legacySource) run(ctx context.Context, legacy kek.LegacyOpener, k kek.KEK, rep *UpgradeReport) error {
	var cur store.Cursor
	for {
		rows, next, err := src.page(ctx, cur)
		if err != nil {
			return errors.Join(errors.New("egauth: listing v0.16 secrets"), err)
		}
		if len(rows) == 0 {
			return nil
		}
		if !next.After(cur) {
			return errors.New("egauth: v0.16 listing did not advance its cursor")
		}
		for _, r := range rows {
			if err := r.upgrade(ctx, legacy, k, rep); err != nil {
				return err
			}
		}
		cur = next
	}
}

type faultProbe struct {
	inner kek.LegacyOpener
	fault error
}

func (p *faultProbe) OpenLegacy(ctx context.Context, blob []byte, aad kek.AAD) ([]byte, error) {
	pt, err := p.inner.OpenLegacy(ctx, blob, aad)
	if err != nil && !errors.Is(err, kek.ErrOpenFailed) && !errors.Is(err, kek.ErrMalformed) {
		p.fault = err
	}
	return pt, err
}

func (r legacyRow) upgrade(ctx context.Context, legacy kek.LegacyOpener, k kek.KEK, rep *UpgradeReport) error {
	ref, err := r.ref()
	if err != nil {
		rep.Unopenable = append(rep.Unopenable, r.row)
		return nil
	}
	probe := &faultProbe{inner: legacy}
	pt, err := sealing.OpenLegacy(ctx, probe, ref, r.sealed)
	if err != nil {
		if probe.fault != nil || ctx.Err() != nil {
			return errors.Join(errors.New("egauth: the legacy opener failed"), probe.fault, ctx.Err())
		}
		rep.Unopenable = append(rep.Unopenable, r.row)
		return nil
	}
	defer clear(pt)
	ct, err := sealing.Seal(ctx, k, ref, pt)
	if err != nil {
		return errors.Join(errors.New("egauth: re-sealing a v0.16 secret"), err)
	}
	ok, err := r.replace(ctx, ct)
	if err != nil {
		return errors.Join(errors.New("egauth: storing a re-sealed v0.16 secret"), err)
	}
	if ok {
		rep.Upgraded++
	} else {
		rep.Concurrent++
	}
	return nil
}

func mfaSource(st mfa.Store) legacySource {
	return legacySource{page: func(ctx context.Context, after store.Cursor) ([]legacyRow, store.Cursor, error) {
		page, next, err := st.V016Sealed(ctx, after, upgradePageSize)
		if err != nil {
			return nil, after, err
		}
		out := make([]legacyRow, len(page))
		for i, p := range page {
			out[i] = legacyRow{
				row:    UpgradeRow{Kind: "mfa_totp", Tenant: p.Ref.Subject.Tenant, ID: p.Ref.Subject.User.String()},
				ref:    func() (sealing.Ref, error) { return sealing.TOTPSecret(p.Ref.Subject) },
				sealed: p.Sealed,
				replace: func(ctx context.Context, sealed []byte) (bool, error) {
					return st.ReplaceSealed(ctx, mfa.Reseal{Ref: p.Ref, Old: p.Sealed, New: sealed})
				},
			}
		}
		return out, next, nil
	}}
}

func federationSource(st fedstore.Store) legacySource {
	return legacySource{page: func(ctx context.Context, after store.Cursor) ([]legacyRow, store.Cursor, error) {
		page, next, err := st.V016Sealed(ctx, after, upgradePageSize)
		if err != nil {
			return nil, after, err
		}
		out := make([]legacyRow, len(page))
		for i, p := range page {
			out[i] = legacyRow{
				row:    UpgradeRow{Kind: "oauth_oidc_providers", Tenant: p.Ref.Tenant, ID: p.Ref.Provider},
				ref:    func() (sealing.Ref, error) { return sealing.OAuthClientSecret(p.Ref.Tenant, p.Ref.Provider) },
				sealed: p.Sealed,
				replace: func(ctx context.Context, sealed []byte) (bool, error) {
					return st.ReplaceSealed(ctx, fedstore.Reseal{Ref: p.Ref, Old: p.Sealed, New: sealed})
				},
			}
		}
		return out, next, nil
	}}
}

func keysSource(st keys.Store) legacySource {
	return legacySource{page: func(ctx context.Context, after store.Cursor) ([]legacyRow, store.Cursor, error) {
		page, next, err := st.V016Sealed(ctx, after, upgradePageSize)
		if err != nil {
			return nil, after, err
		}
		out := make([]legacyRow, len(page))
		for i, p := range page {
			out[i] = legacyRow{
				row:    UpgradeRow{Kind: "keystore_keys", Tenant: p.Ref.Tenant, ID: p.Ref.KeyID},
				ref:    func() (sealing.Ref, error) { return sealing.SigningKey(p.Ref.Tenant, p.Ref.KeyID) },
				sealed: p.Sealed,
				replace: func(ctx context.Context, sealed []byte) (bool, error) {
					return st.ReplaceSealed(ctx, keys.Reseal{Ref: p.Ref, Old: p.Sealed, New: sealed})
				},
			}
		}
		return out, next, nil
	}}
}
