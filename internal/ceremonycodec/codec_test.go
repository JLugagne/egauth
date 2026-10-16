package ceremonycodec_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/ceremony"
)

func mustCode(t *testing.T, s *ceremonycodec.Sealer, code string) ceremonycodec.Code {
	t.Helper()
	c, err := ceremonycodec.NewCode(s, code)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type roundTrip struct {
	kind   ceremony.Kind
	run    func(t *testing.T)
	refuse func(t *testing.T)
}

func caseFor[P any](c ceremonycodec.Codec[P], good, bad P) roundTrip {
	return roundTrip{
		kind: c.Kind(),
		run: func(t *testing.T) {
			b, err := c.Encode(good)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, good) {
				t.Fatalf("round trip = %#v, want %#v", got, good)
			}
		},
		refuse: func(t *testing.T) {
			if _, err := c.Encode(bad); !errors.Is(err, ceremonycodec.ErrMalformedPayload) {
				t.Fatalf("Encode(invalid) = %v, want ErrMalformedPayload", err)
			}
		},
	}
}

func allCases(t *testing.T) []roundTrip {
	code := mustCode(t, sealer(t, clock.NewTest(base).Clock()), "123456")
	web := ceremonycodec.WebAuthn{Session: []byte(`{"challenge":"abc"}`)}
	oauth := ceremonycodec.OAuth{Provider: "google", PKCEVerifier: strings.Repeat("v", 43), Nonce: "n-1", RedirectURI: "https://app.example/oauth/google/callback"}
	return []roundTrip{
		caseFor(ceremonycodec.MFAFlow(), ceremonycodec.Empty{}, ceremonycodec.Empty{}),
		caseFor(ceremonycodec.PasskeyRegistration(), web, ceremonycodec.WebAuthn{}),
		caseFor(ceremonycodec.MFAPasskey(), web, ceremonycodec.WebAuthn{Session: make([]byte, 2049)}),
		caseFor(ceremonycodec.MagicLink(), ceremonycodec.Empty{}, ceremonycodec.Empty{}),
		caseFor(ceremonycodec.EmailCode(), code, ceremonycodec.Code{}),
		caseFor(ceremonycodec.SMSCode(), code, ceremonycodec.Code{}),
		caseFor(ceremonycodec.PhoneVerification(), ceremonycodec.PhoneCode{Code: code, Phone: "+33600000000"}, ceremonycodec.PhoneCode{Code: code}),
		caseFor(ceremonycodec.PasswordReset(), ceremonycodec.Empty{}, ceremonycodec.Empty{}),
		caseFor(ceremonycodec.PendingRegistration(), ceremonycodec.Registration{Email: "a@example.com", PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"}, ceremonycodec.Registration{Email: "a@example.com"}),
		caseFor(ceremonycodec.EmailVerification(), ceremonycodec.Address{Address: "a@example.com"}, ceremonycodec.Address{}),
		caseFor(ceremonycodec.EmailChange(), ceremonycodec.Address{Address: "new@example.com"}, ceremonycodec.Address{Address: strings.Repeat("a", 321)}),
		caseFor(ceremonycodec.RecoveryEmail(), ceremonycodec.Address{Address: "r@example.com"}, ceremonycodec.Address{}),
		caseFor(ceremonycodec.SecurityRevert(), ceremonycodec.Revert{Address: "a@example.com", Event: 3}, ceremonycodec.Revert{Address: "a@example.com"}),
		caseFor(ceremonycodec.Exchange(), ceremonycodec.Empty{}, ceremonycodec.Empty{}),
		caseFor(ceremonycodec.DiscoverablePasskey(), web, ceremonycodec.WebAuthn{}),
		caseFor(ceremonycodec.UsernameFirstPasskey(), web, ceremonycodec.WebAuthn{}),
		caseFor(ceremonycodec.OAuthState(), oauth, ceremonycodec.OAuth{Provider: "google", PKCEVerifier: "short", RedirectURI: "https://x"}),
		caseFor(ceremonycodec.ExternalLogin(), ceremonycodec.External{Name: "sso"}, ceremonycodec.External{}),
		caseFor(ceremonycodec.PasswordResetCode(), code, ceremonycodec.Code{}),
	}
}

func TestEveryKindHasExactlyOneCodec(t *testing.T) {
	var kinds []ceremony.Kind
	for _, c := range allCases(t) {
		kinds = append(kinds, c.kind)
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, ceremony.All()) {
		t.Fatalf("codec kinds = %v, want every kind once: %v", kinds, ceremony.All())
	}
}

func TestPayloadRoundTrips(t *testing.T) {
	for _, c := range allCases(t) {
		t.Run(c.kind.String(), func(t *testing.T) {
			c.run(t)
			if c.kind != ceremony.MFAFlow && c.kind != ceremony.MagicLink && c.kind != ceremony.PasswordReset && c.kind != ceremony.Exchange {
				c.refuse(t)
			}
		})
	}
}

func TestPayloadOfAnotherKindIsRefused(t *testing.T) {
	b, err := ceremonycodec.EmailVerification().Encode(ceremonycodec.Address{Address: "a@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ceremonycodec.EmailChange().Decode(b); !errors.Is(err, ceremonycodec.ErrWrongKind) {
		t.Fatalf("EmailChange.Decode(EmailVerification payload) = %v, want ErrWrongKind", err)
	}
	if _, err := ceremonycodec.RecoveryEmail().Decode(b); !errors.Is(err, ceremonycodec.ErrWrongKind) {
		t.Fatalf("RecoveryEmail.Decode(EmailVerification payload) = %v, want ErrWrongKind", err)
	}
}

func TestMalformedPayloadsAreRefused(t *testing.T) {
	c := ceremonycodec.EmailVerification()
	prefix := []byte{1, byte(ceremony.EmailVerification)}
	for name, b := range map[string][]byte{
		"empty":         nil,
		"version 2":     append([]byte{2, byte(ceremony.EmailVerification)}, `{"Address":"a"}`...),
		"unknown field": append(bytes.Clone(prefix), `{"Address":"a","Admin":true}`...),
		"trailing data": append(bytes.Clone(prefix), `{"Address":"a"}{}`...),
		"invalid value": append(bytes.Clone(prefix), `{"Address":""}`...),
		"not json":      append(bytes.Clone(prefix), `nope`...),
		"oversized":     append(bytes.Clone(prefix), make([]byte, 5000)...),
	} {
		if _, err := c.Decode(b); !errors.Is(err, ceremonycodec.ErrMalformedPayload) {
			t.Errorf("%s: Decode = %v, want ErrMalformedPayload", name, err)
		}
	}
	var zero ceremonycodec.Codec[ceremonycodec.Address]
	if _, err := zero.Encode(ceremonycodec.Address{Address: "a"}); !errors.Is(err, ceremonycodec.ErrWrongKind) {
		t.Errorf("zero Codec Encode = %v", err)
	}
	if _, err := zero.Decode(append(bytes.Clone(prefix), `{"Address":"a"}`...)); !errors.Is(err, ceremonycodec.ErrWrongKind) {
		t.Errorf("zero Codec Decode = %v", err)
	}
}

func TestCodeComparesDigestsOnly(t *testing.T) {
	s := sealer(t, clock.NewTest(base).Clock())
	c := mustCode(t, s, "424242")
	if !c.Matches(s, "424242") {
		t.Fatal("code does not match itself")
	}
	for _, other := range []string{"424243", "", "4242420", strings.Repeat("4", 65)} {
		if c.Matches(s, other) {
			t.Fatalf("code matches %q", other)
		}
	}
	if (ceremonycodec.Code{}).Matches(s, "") {
		t.Fatal("the zero Code matches")
	}
	b, err := ceremonycodec.SMSCode().Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("424242")) {
		t.Fatal("encoded payload contains the code in clear")
	}
	back, err := ceremonycodec.SMSCode().Decode(b)
	if err != nil || !back.Matches(s, "424242") {
		t.Fatalf("decoded code = %v, %v", back, err)
	}
	for _, bad := range []string{"", strings.Repeat("9", 65)} {
		if _, err := ceremonycodec.NewCode(s, bad); !errors.Is(err, ceremonycodec.ErrMalformedPayload) {
			t.Fatalf("NewCode(%q) = %v", bad, err)
		}
	}
}

func TestHandlesAre256BitRandom(t *testing.T) {
	a, err := ceremonycodec.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ceremonycodec.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	if a.Encode() == b.Encode() {
		t.Fatal("two handles are equal")
	}
	raw, err := base64.RawURLEncoding.DecodeString(a.Encode())
	if err != nil || len(raw) != 32 {
		t.Fatalf("handle carries %d bytes, want 32", len(raw))
	}
	sum := sha256.Sum256(raw)
	if !bytes.Equal(a.Hash(), sum[:]) {
		t.Fatal("Hash is not SHA-256 of the raw handle")
	}
	parsed, err := ceremonycodec.ParseHandle(a.Encode())
	if err != nil || !bytes.Equal(parsed.Hash(), a.Hash()) {
		t.Fatalf("ParseHandle round trip = %v", err)
	}
	enc := a.Encode()
	last := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", enc[len(enc)-1])
	malleable := enc[:len(enc)-1] + string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[last^1])
	for _, bad := range []string{"", "123456", enc[:len(enc)-1], enc + "A", enc + "=", strings.Repeat("*", len(enc)), malleable} {
		if _, err := ceremonycodec.ParseHandle(bad); !errors.Is(err, ceremonycodec.ErrInvalidHandle) {
			t.Errorf("ParseHandle(%q) = %v, want ErrInvalidHandle", bad, err)
		}
	}
	if !(ceremonycodec.Handle{}).IsZero() || a.IsZero() {
		t.Fatal("IsZero is wrong")
	}
}

func dataKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, ceremonycodec.DataKeyBytes)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

var base = time.Date(2026, 10, 8, 9, 30, 15, 123456789, time.UTC)

func sealer(t *testing.T, c clock.Clock) *ceremonycodec.Sealer {
	t.Helper()
	s, err := ceremonycodec.NewSealer(dataKey(t), c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func tenant(t *testing.T, s string) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

var oauthState = ceremonycodec.OAuth{Provider: "google", PKCEVerifier: strings.Repeat("p", 64), Nonce: "nonce", RedirectURI: "https://app.example/oauth/google/callback"}

func TestNewSealerRejectsBadKeys(t *testing.T) {
	for name, k := range map[string][]byte{
		"short":    make([]byte, 16),
		"long":     make([]byte, 33),
		"all zero": make([]byte, 32),
		"pattern":  bytes.Repeat([]byte{1, 2, 3, 4}, 8),
	} {
		if _, err := ceremonycodec.NewSealer(k, clock.Clock{}); !errors.Is(err, ceremonycodec.ErrInvalidDataKey) {
			t.Errorf("%s: NewSealer = %v", name, err)
		}
	}
}

func TestStatelessHandleRoundTrip(t *testing.T) {
	tc := clock.NewTest(base)
	s := sealer(t, tc.Clock())
	p := principaltest.FullPending()
	issued, err := ceremonycodec.OAuthState().Seal(s, p, oauthState)
	if err != nil {
		t.Fatal(err)
	}
	if want := ceremony.OAuthState.ExpiresAt(p.ExpiresAt(), base); !issued.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", issued.ExpiresAt, want)
	}
	opened, err := ceremonycodec.OAuthState().Open(s, tenant(t, "tenant-full"), issued.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Payload != oauthState || !opened.ExpiresAt.Equal(issued.ExpiresAt) {
		t.Fatalf("opened = %#v", opened)
	}
	if !reflect.DeepEqual(opened.Pending, p) {
		t.Fatal("opened Pending differs from the sealed one")
	}
	raw, err := base64.RawURLEncoding.DecodeString(issued.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); !bytes.Equal(opened.HandleHash, sum[:]) {
		t.Fatal("HandleHash is not SHA-256 of the decoded handle")
	}
	for _, leak := range []string{oauthState.PKCEVerifier, "tenant-full", "google"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("handle carries %q in clear", leak)
		}
	}
	again, err := ceremonycodec.OAuthState().Seal(s, p, oauthState)
	if err != nil || again.Handle == issued.Handle {
		t.Fatalf("sealing is not randomised: %v", err)
	}
}

func TestStatelessHandleExpiryIsAlwaysChecked(t *testing.T) {
	tc := clock.NewTest(base)
	s := sealer(t, tc.Clock())
	codec := ceremonycodec.DiscoverablePasskey()
	issued, err := codec.Seal(s, principaltest.FullPending(), ceremonycodec.WebAuthn{Session: []byte("challenge")})
	if err != nil {
		t.Fatal(err)
	}
	if want := base.Add(ceremony.DiscoverablePasskey.TTL()); !issued.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want now + TTL %v", issued.ExpiresAt, want)
	}
	tc.Set(issued.ExpiresAt.Add(-time.Nanosecond))
	if _, err := codec.Open(s, tenant(t, "tenant-full"), issued.Handle); err != nil {
		t.Fatalf("Open just before expiry = %v", err)
	}
	for _, at := range []time.Time{issued.ExpiresAt, issued.ExpiresAt.Add(time.Hour)} {
		tc.Set(at)
		_, err := codec.Open(s, tenant(t, "tenant-full"), issued.Handle)
		if !errors.Is(err, ceremonycodec.ErrExpired) || !errors.Is(err, ceremonycodec.ErrInvalidHandle) {
			t.Fatalf("Open at %v = %v, want ErrExpired", at, err)
		}
	}
}

func TestStatelessHandleNeverOutlivesItsPending(t *testing.T) {
	p := principaltest.FullPending()
	tc := clock.NewTest(p.ExpiresAt().Add(-2 * time.Minute))
	s := sealer(t, tc.Clock())
	issued, err := ceremonycodec.OAuthState().Seal(s, p, oauthState)
	if err != nil {
		t.Fatal(err)
	}
	if !issued.ExpiresAt.Equal(p.ExpiresAt()) {
		t.Fatalf("ExpiresAt = %v, want the Pending expiry %v", issued.ExpiresAt, p.ExpiresAt())
	}
	tc.Set(p.ExpiresAt())
	if _, err := ceremonycodec.OAuthState().Seal(s, p, oauthState); !errors.Is(err, ceremonycodec.ErrExpired) {
		t.Fatalf("Seal of an expired Pending = %v, want ErrExpired", err)
	}
}

func TestStatelessHandleWrongTenant(t *testing.T) {
	s := sealer(t, clock.NewTest(base).Clock())
	issued, err := ceremonycodec.OAuthState().Seal(s, principaltest.FullPending(), oauthState)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []principal.TenantID{tenant(t, "tenant-b"), {}, tenant(t, "tenant-full-x")} {
		_, err := ceremonycodec.OAuthState().Open(s, other, issued.Handle)
		if !errors.Is(err, ceremonycodec.ErrWrongTenant) || !errors.Is(err, ceremonycodec.ErrInvalidHandle) {
			t.Fatalf("Open under tenant %q = %v, want ErrWrongTenant", other, err)
		}
	}
}

func TestStatelessHandleWrongKind(t *testing.T) {
	s := sealer(t, clock.NewTest(base).Clock())
	issued, err := ceremonycodec.DiscoverablePasskey().Seal(s, principaltest.FullPending(), ceremonycodec.WebAuthn{Session: []byte("c")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ceremonycodec.UsernameFirstPasskey().Open(s, tenant(t, "tenant-full"), issued.Handle)
	if !errors.Is(err, ceremonycodec.ErrWrongKind) || !errors.Is(err, ceremonycodec.ErrInvalidHandle) {
		t.Fatalf("UsernameFirstPasskey.Open(discoverable handle) = %v, want ErrWrongKind", err)
	}
	if _, err := ceremonycodec.ExternalLogin().Open(s, tenant(t, "tenant-full"), issued.Handle); !errors.Is(err, ceremonycodec.ErrWrongKind) {
		t.Fatalf("ExternalLogin.Open(discoverable handle) = %v, want ErrWrongKind", err)
	}
}

func TestStoredKindsAreNeverSealedAsHandles(t *testing.T) {
	s := sealer(t, clock.NewTest(base).Clock())
	if _, err := ceremonycodec.MagicLink().Seal(s, principaltest.FullPending(), ceremonycodec.Empty{}); !errors.Is(err, ceremonycodec.ErrNotStateless) {
		t.Fatalf("MagicLink.Seal = %v, want ErrNotStateless", err)
	}
	if _, err := ceremonycodec.MagicLink().Open(s, tenant(t, "tenant-full"), "x"); !errors.Is(err, ceremonycodec.ErrInvalidHandle) {
		t.Fatalf("MagicLink.Open = %v, want ErrInvalidHandle", err)
	}
	if _, err := ceremonycodec.OAuthState().Seal(nil, principaltest.FullPending(), oauthState); !errors.Is(err, ceremonycodec.ErrNotStateless) {
		t.Fatalf("Seal with a nil Sealer = %v", err)
	}
}

func TestStatelessHandleTamperIsRefused(t *testing.T) {
	tc := clock.NewTest(base)
	s := sealer(t, tc.Clock())
	codec := ceremonycodec.OAuthState()
	issued, err := codec.Seal(s, principaltest.FullPending(), oauthState)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(issued.Handle)
	if err != nil {
		t.Fatal(err)
	}
	var tampered []string
	for _, i := range []int{0, 1, 30, len(raw) / 2, len(raw) - 1} {
		b := bytes.Clone(raw)
		b[i] ^= 0x01
		tampered = append(tampered, base64.RawURLEncoding.EncodeToString(b))
	}
	tampered = append(tampered,
		"",
		issued.Handle[:len(issued.Handle)-4],
		issued.Handle+"AAAA",
		base64.RawURLEncoding.EncodeToString(raw[:30]),
		strings.Repeat("A", 9000),
		issued.Handle+"=",
	)
	if mod := len(raw) % 3; mod != 0 {
		alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		last := strings.IndexByte(alphabet, issued.Handle[len(issued.Handle)-1])
		tampered = append(tampered, issued.Handle[:len(issued.Handle)-1]+string(alphabet[last^1]))
	}
	for _, h := range tampered {
		if _, err := codec.Open(s, tenant(t, "tenant-full"), h); !errors.Is(err, ceremonycodec.ErrInvalidHandle) {
			t.Errorf("Open(tampered) = %v, want ErrInvalidHandle", err)
		}
	}
	other := sealer(t, tc.Clock())
	if _, err := codec.Open(other, tenant(t, "tenant-full"), issued.Handle); !errors.Is(err, ceremonycodec.ErrInvalidHandle) {
		t.Fatalf("Open under another data key = %v, want ErrInvalidHandle", err)
	}
}

func TestSealerUsesTheDataKeyNotACopyOfTheCaller(t *testing.T) {
	tc := clock.NewTest(base)
	key := dataKey(t)
	s, err := ceremonycodec.NewSealer(key, tc.Clock())
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ceremonycodec.OAuthState().Seal(s, principaltest.FullPending(), oauthState)
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	if _, err := ceremonycodec.OAuthState().Open(s, tenant(t, "tenant-full"), issued.Handle); err != nil {
		t.Fatalf("Open after the caller zeroed its key buffer: %v", err)
	}
}

func TestSecretsAreRedacted(t *testing.T) {
	h, err := ceremonycodec.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	s := sealer(t, clock.NewTest(base).Clock())
	issued, err := ceremonycodec.OAuthState().Seal(s, principaltest.FullPending(), oauthState)
	if err != nil {
		t.Fatal(err)
	}
	values := []any{
		h, issued, s, oauthState, mustCode(t, s, "987654"),
		ceremonycodec.PhoneCode{Code: mustCode(t, s, "987654"), Phone: "+33"},
		ceremonycodec.Registration{Email: "a@example.com", PasswordHash: "$argon2id$secret-hash"},
		ceremonycodec.WebAuthn{Session: []byte("challenge-bytes")},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var out strings.Builder
	for _, v := range values {
		logger.Info("v", "v", v)
		fmt.Fprintf(&out, "%v %+v %#v %s\n", v, v, v, v)
	}
	all := out.String() + buf.String()
	for _, secret := range []string{h.Encode(), issued.Handle, oauthState.PKCEVerifier, "987654", "secret-hash", "challenge-bytes"} {
		if strings.Contains(all, secret) {
			t.Fatalf("formatted values leak %q:\n%s", secret, all)
		}
	}
}

func TestOpenedPendingKeepsItsTenant(t *testing.T) {
	s := sealer(t, clock.NewTest(base).Clock())
	p := principaltest.FullPending()
	issued, err := ceremonycodec.OAuthState().Seal(s, p, oauthState)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := ceremonycodec.OAuthState().Open(s, p.Tenant(), issued.Handle)
	if err != nil {
		t.Fatal(err)
	}
	want := p.Tenant()
	if opened.Pending.Tenant() != want {
		t.Fatal("opened Pending is of another tenant")
	}
}

func TestConcurrentBeginsDoNotEvictEachOther(t *testing.T) {
	s := sealer(t, clock.NewTest(base).Clock())
	codec := ceremonycodec.DiscoverablePasskey()
	first, err := codec.Seal(s, principaltest.FullPending(), ceremonycodec.WebAuthn{Session: []byte("autofill")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := codec.Seal(s, principaltest.FullPending(), ceremonycodec.WebAuthn{Session: []byte("button")})
	if err != nil {
		t.Fatal(err)
	}
	for want, h := range map[string]string{"autofill": first.Handle, "button": second.Handle} {
		opened, err := codec.Open(s, tenant(t, "tenant-full"), h)
		if err != nil || string(opened.Payload.Session) != want {
			t.Fatalf("begin %q no longer opens after another begin: %v", want, err)
		}
	}
}
