package tokens_test

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/tokens"
)

var (
	family = uuid.MustParse("11111111-2222-4333-8444-555555555555")
	hash32 = bytes.Repeat([]byte{0xab}, tokens.HashLen)
)

func sealed(t *testing.T, a core.SessionAttrs) principal.Sealed {
	t.Helper()
	s, err := core.Seal(a)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func spec(t *testing.T) tokens.RefreshSpec {
	t.Helper()
	a := principaltest.Full()
	return tokens.RefreshSpec{
		TokenHash:         slices.Clone(hash32),
		Family:            family,
		Attrs:             a,
		AppClaims:         []byte(`{"roles":["admin"]}`),
		ClientFingerprint: []byte("fp-client-a"),
		IdleTTL:           time.Hour,
		MaxLifetime:       30 * 24 * time.Hour,
		Now:               a.CreatedAt().Add(24 * time.Hour),
	}
}

func TestNewRefreshRecordDerivesIndexFieldsFromAttrs(t *testing.T) {
	s := spec(t)
	r, err := tokens.NewRefreshRecord(s, core.Seal)
	if err != nil {
		t.Fatal(err)
	}
	a := s.Attrs
	if r.Subject() != a.Subject() || r.Tenant() != a.Subject().Tenant || r.Lineage() != a.Lineage() || r.Epoch() != a.Epoch() {
		t.Fatalf("index fields not derived from the attributes: %v %v %v %d", r.Subject(), r.Tenant(), r.Lineage(), r.Epoch())
	}
	if r.Family() != family || !bytes.Equal(r.TokenHash(), hash32) || !bytes.Equal(r.Sealed().Bytes(), sealed(t, a).Bytes()) {
		t.Fatal("family, hash or sealed bytes not kept verbatim")
	}
	if !r.FamilyExpiresAt().Equal(a.CreatedAt().Add(s.MaxLifetime)) {
		t.Fatalf("family must expire MaxLifetime after the lineage was admitted, got %s", r.FamilyExpiresAt())
	}
	if !r.IdleExpiresAt().Equal(s.Now.Add(s.IdleTTL)) || !r.CreatedAt().Equal(s.Now) {
		t.Fatal("idle expiry and creation time must come from Now")
	}
	got, err := core.Unseal(r.Sealed())
	if err != nil || !reflect.DeepEqual(got, a) {
		t.Fatalf("sealed attributes do not round-trip: %v", err)
	}
}

func TestNewRefreshRecordCopiesItsInputs(t *testing.T) {
	s := spec(t)
	r, err := tokens.NewRefreshRecord(s, core.Seal)
	if err != nil {
		t.Fatal(err)
	}
	s.TokenHash[0] ^= 0xff
	s.AppClaims[0] = 'X'
	s.ClientFingerprint[0] = 'X'
	r.TokenHash()[1] ^= 0xff
	if !bytes.Equal(r.TokenHash(), hash32) || r.AppClaims()[0] != '{' || r.ClientFingerprint()[0] != 'f' {
		t.Fatal("record aliases caller memory")
	}
}

func TestIdleExpiryNeverOutlivesTheFamily(t *testing.T) {
	s := spec(t)
	s.MaxLifetime = 24*time.Hour + 30*time.Minute
	r, err := tokens.NewRefreshRecord(s, core.Seal)
	if err != nil {
		t.Fatal(err)
	}
	if !r.IdleExpiresAt().Equal(r.FamilyExpiresAt()) {
		t.Fatalf("idle expiry %s must be clamped to the family end %s", r.IdleExpiresAt(), r.FamilyExpiresAt())
	}
}

func TestNewRefreshRecordRefusesAnExhaustedLineage(t *testing.T) {
	s := spec(t)
	s.MaxLifetime = 24 * time.Hour
	if _, err := tokens.NewRefreshRecord(s, core.Seal); !errors.Is(err, tokens.ErrLifetimeExceeded) {
		t.Fatalf("want ErrLifetimeExceeded, got %v", err)
	}
}

func TestNewRefreshRecordRefusesIncompleteSpecs(t *testing.T) {
	cases := map[string]func(*tokens.RefreshSpec){
		"zero attrs":       func(s *tokens.RefreshSpec) { s.Attrs = core.SessionAttrs{} },
		"nil family":       func(s *tokens.RefreshSpec) { s.Family = uuid.Nil },
		"short hash":       func(s *tokens.RefreshSpec) { s.TokenHash = []byte("123456") },
		"long hash":        func(s *tokens.RefreshSpec) { s.TokenHash = append(slices.Clone(hash32), 1) },
		"no idle ttl":      func(s *tokens.RefreshSpec) { s.IdleTTL = 0 },
		"no max lifetime":  func(s *tokens.RefreshSpec) { s.MaxLifetime = -time.Hour },
		"no now":           func(s *tokens.RefreshSpec) { s.Now = time.Time{} },
		"long fingerprint": func(s *tokens.RefreshSpec) { s.ClientFingerprint = make([]byte, tokens.MaxFingerprintLen+1) },
		"huge claims":      func(s *tokens.RefreshSpec) { s.AppClaims = make([]byte, tokens.MaxAppClaimsLen+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := spec(t)
			mutate(&s)
			if _, err := tokens.NewRefreshRecord(s, core.Seal); !errors.Is(err, tokens.ErrInvalidRecord) {
				t.Fatalf("want ErrInvalidRecord, got %v", err)
			}
		})
	}
}

func rowOf(r tokens.RefreshRecord) tokens.RefreshRow {
	return tokens.RefreshRow{
		TokenHash:         r.TokenHash(),
		Family:            r.Family(),
		Subject:           r.Subject(),
		Lineage:           r.Lineage(),
		Sealed:            r.Sealed(),
		AppClaims:         r.AppClaims(),
		SecurityEpoch:     r.Epoch(),
		ClientFingerprint: r.ClientFingerprint(),
		IdleExpiresAt:     r.IdleExpiresAt(),
		FamilyExpiresAt:   r.FamilyExpiresAt(),
		CreatedAt:         r.CreatedAt(),
	}
}

func TestRestoreRefreshRecordRoundTrips(t *testing.T) {
	r, err := tokens.NewRefreshRecord(spec(t), core.Seal)
	if err != nil {
		t.Fatal(err)
	}
	back, err := tokens.RestoreRefreshRecord(rowOf(r))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, r) {
		t.Fatal("restored record differs from the original")
	}
}

func TestRestoreRefreshRecordRefusesRowsNewCouldNotProduce(t *testing.T) {
	r, err := tokens.NewRefreshRecord(spec(t), core.Seal)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*tokens.RefreshRow){
		"idle after family":   func(w *tokens.RefreshRow) { w.IdleExpiresAt = w.FamilyExpiresAt.Add(time.Second) },
		"idle before created": func(w *tokens.RefreshRow) { w.IdleExpiresAt = w.CreatedAt },
		"zero subject":        func(w *tokens.RefreshRow) { w.Subject = principal.Subject{} },
		"nil lineage":         func(w *tokens.RefreshRow) { w.Lineage = uuid.Nil },
		"no created":          func(w *tokens.RefreshRow) { w.CreatedAt = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := rowOf(r)
			mutate(&w)
			if _, err := tokens.RestoreRefreshRecord(w); !errors.Is(err, tokens.ErrInvalidRecord) {
				t.Fatalf("want ErrInvalidRecord, got %v", err)
			}
		})
	}
	if !(tokens.RefreshRecord{}).IsZero() || r.IsZero() {
		t.Fatal("IsZero must tell a built record from a literal")
	}
}

func TestAPIKeyValidate(t *testing.T) {
	a := principaltest.Full()
	now := a.CreatedAt()
	good := tokens.APIKey{
		ID: family, Owner: a.Subject(), Kind: "automation", Name: "ci", KeyHash: slices.Clone(hash32),
		AppClaims: []byte(`{"roles":["ci"]}`), CreatedEpoch: 7, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	never := good
	never.ExpiresAt = time.Time{}
	if err := never.Validate(); err != nil {
		t.Fatalf("a key without expiry is valid: %v", err)
	}
	cases := map[string]func(*tokens.APIKey){
		"nil id":        func(k *tokens.APIKey) { k.ID = uuid.Nil },
		"no owner":      func(k *tokens.APIKey) { k.Owner = principal.Subject{} },
		"no kind":       func(k *tokens.APIKey) { k.Kind = "" },
		"short hash":    func(k *tokens.APIKey) { k.KeyHash = []byte("abc") },
		"no created":    func(k *tokens.APIKey) { k.CreatedAt = time.Time{} },
		"expired early": func(k *tokens.APIKey) { k.ExpiresAt = k.CreatedAt },
		"huge claims":   func(k *tokens.APIKey) { k.AppClaims = make([]byte, tokens.MaxAppClaimsLen+1) },
		"long name":     func(k *tokens.APIKey) { k.Name = string(make([]byte, tokens.MaxAPIKeyLabelLen+1)) },
	}
	for name, mutate := range cases {
		k := good
		mutate(&k)
		if err := k.Validate(); !errors.Is(err, tokens.ErrInvalidRecord) {
			t.Errorf("%s: want ErrInvalidRecord, got %v", name, err)
		}
	}
}

func TestFamilyStateLive(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	live := tokens.FamilyState{ExpiresAt: now.Add(time.Minute)}
	if !live.Live(now) {
		t.Fatal("unrevoked, unexpired family must be live")
	}
	if (tokens.FamilyState{Revoked: true, ExpiresAt: now.Add(time.Minute)}).Live(now) {
		t.Fatal("revoked family must not be live")
	}
	if (tokens.FamilyState{ExpiresAt: now}).Live(now) || (tokens.FamilyState{}).Live(now) {
		t.Fatal("expired or zero family must not be live")
	}
}

func TestStoreContract(t *testing.T) {
	st := reflect.TypeOf((*tokens.Store)(nil)).Elem()
	for _, base := range []reflect.Type{
		reflect.TypeOf((*store.Base)(nil)).Elem(),
		reflect.TypeOf((*store.Reaper)(nil)).Elem(),
	} {
		if !st.Implements(base) {
			t.Fatalf("tokens.Store must embed %s", base)
		}
	}
	for _, m := range []string{
		"Create", "Get", "ConsumeForRotation", "Reissue", "FamilyState", "RevokeFamily", "RevokeForSubject",
		"RevocationsSince", "DeleteForSubject", "CreateAPIKey", "GetAPIKey", "ListAPIKeys", "RevokeAPIKey",
	} {
		if _, ok := st.MethodByName(m); !ok {
			t.Errorf("tokens.Store lacks %s", m)
		}
	}
	if tokens.ReuseGrace <= 0 || tokens.ReuseGrace > time.Minute {
		t.Fatalf("ReuseGrace %s must be a short positive window", tokens.ReuseGrace)
	}
	all := []error{tokens.ErrReused, tokens.ErrConcurrent, tokens.ErrRevoked, tokens.ErrInvalidRecord, tokens.ErrLifetimeExceeded}
	for i, a := range all {
		for j, b := range all {
			if (i == j) != errors.Is(a, b) {
				t.Fatalf("errors %v and %v must be distinct", a, b)
			}
		}
	}
}

func TestRotationAndReissueRequestsCarryOnlyASealedRecordAndOneHash(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(tokens.RotationRequest{}), reflect.TypeOf(tokens.ReissueRequest{})} {
		records, hashes := 0, 0
		for i := 0; i < typ.NumField(); i++ {
			switch f := typ.Field(i); f.Type {
			case reflect.TypeOf(tokens.RefreshRecord{}):
				records++
			case reflect.TypeOf([]byte(nil)):
				hashes++
			case reflect.TypeOf(uuid.UUID{}):
			default:
				t.Errorf("%s.%s: unexpected field type %s", typ.Name(), f.Name, f.Type)
			}
		}
		if records != 1 || hashes > 1 {
			t.Errorf("%s must wrap exactly one record and at most one hash", typ.Name())
		}
	}
}
