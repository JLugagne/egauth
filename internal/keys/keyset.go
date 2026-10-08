package keys

import (
	"cmp"
	"context"
	"errors"
	"time"

	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	storekeys "github.com/JLugagne/egauth/store/keys"
)

var errLegacyKey = errors.New("keys: v0.16 key material was not upgraded; run egauth.UpgradeSecretsV016")

type entry struct {
	meta     storekeys.Key
	signer   signing.Signer
	verifier signing.Verifier
}

type keyset struct {
	entries map[string]entry
}

func newer(a, b storekeys.Key) bool {
	return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.KeyID, b.KeyID)) > 0
}

func (ks *keyset) signerAt(now time.Time) (signing.Signer, bool) {
	var best *entry
	for _, e := range ks.entries {
		if e.signer.IsZero() || !e.meta.IsActive(now) {
			continue
		}
		if best == nil || newer(e.meta, best.meta) {
			best = &e
		}
	}
	if best == nil {
		return signing.Signer{}, false
	}
	return best.signer, true
}

func (ks *keyset) verifierAt(kid string, now time.Time) (signing.Verifier, bool) {
	e, ok := ks.entries[kid]
	if !ok || !e.meta.Verifies(now) {
		return signing.Verifier{}, false
	}
	return e.verifier, true
}

func (ks *keyset) publishedAt(now time.Time) []signing.Verifier {
	var out []signing.Verifier
	for _, e := range ks.entries {
		if e.meta.Verifies(now) && !e.verifier.Symmetric() {
			out = append(out, e.verifier)
		}
	}
	return out
}

func (t *tenantKeys) load(ctx context.Context, tn principal.TenantID) (*keyset, error) {
	rows, err := t.store.VerificationKeys(ctx, tn)
	if err != nil {
		return nil, err
	}
	ks := &keyset{entries: make(map[string]entry, len(rows))}
	for _, k := range rows {
		e, err := t.open(ctx, k)
		if err != nil {
			return nil, errors.Join(errors.New("keys: open key "+k.KeyID), err)
		}
		ks.entries[k.KeyID] = e
	}
	return ks, nil
}

func (t *tenantKeys) open(ctx context.Context, k storekeys.Key) (entry, error) {
	if k.AADVersion != storekeys.AADVersionCurrent {
		return entry{}, errLegacyKey
	}
	ref, err := sealing.SigningKey(k.Tenant, k.KeyID)
	if err != nil {
		return entry{}, err
	}
	opened, err := sealing.Open(ctx, t.kek, ref, k.Sealed)
	if err != nil {
		return entry{}, err
	}
	defer clear(opened.Plaintext)
	s, err := newSigner(k.Alg, k.KeyID, opened.Plaintext)
	if err != nil {
		return entry{}, err
	}
	if opened.Stale {
		t.reseal(ctx, ref, k, opened.Plaintext)
	}
	k.Sealed = nil
	e := entry{meta: k, verifier: s.Verifier()}
	if k.RetiredAt == nil {
		e.signer = s
	}
	return e, nil
}

func (t *tenantKeys) reseal(ctx context.Context, ref sealing.Ref, k storekeys.Key, pt []byte) {
	ct, err := sealing.Seal(ctx, t.kek, ref, pt)
	if err != nil {
		return
	}
	_, _ = t.store.ReplaceSealed(ctx, storekeys.Reseal{
		Ref: storekeys.SealedRef{Tenant: k.Tenant, KeyID: k.KeyID},
		Old: k.Sealed,
		New: ct,
	})
}

func newSigner(alg, kid string, material []byte) (signing.Signer, error) {
	var (
		s   signing.Signer
		err error
	)
	switch alg {
	case signing.AlgEdDSA:
		s, err = signing.EdDSA(kid, material)
	case signing.AlgES256:
		s, err = signing.ES256(kid, material)
	case signing.AlgRS256:
		s, err = signing.RS256(kid, material)
	case signing.AlgHS256:
		s, err = signing.HS256(kid, material)
	default:
		return signing.Signer{}, errors.Join(ErrUnsupportedAlgorithm, errors.New("keys: algorithm "+alg))
	}
	if err != nil {
		return signing.Signer{}, err
	}
	if s.Algorithm() != alg {
		return signing.Signer{}, errors.Join(signing.ErrInvalidKey, errors.New("keys: material is not a "+alg+" key"))
	}
	return s, nil
}
