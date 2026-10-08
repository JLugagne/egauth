package kek_test

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/kek/kektest"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, kek.KeyLength)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func newLocal(t *testing.T, current []byte, previous ...[]byte) *kek.Local {
	t.Helper()
	l, err := kek.NewLocal(current, previous...)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLocalContract(t *testing.T) {
	kektest.Run(t, func(t *testing.T) kek.KEK {
		l, err := kek.NewLocal(randomKey(t))
		if err != nil {
			t.Fatal(err)
		}
		return l
	})
}

func TestNewLocalRejectsBadKeys(t *testing.T) {
	good := randomKey(t)
	cases := map[string][][]byte{
		"short":              {good[:31]},
		"long":               {append(bytes.Clone(good), 0x01)},
		"empty":              {nil},
		"all zero":           {make([]byte, kek.KeyLength)},
		"repeated byte":      {bytes.Repeat([]byte{0x41}, kek.KeyLength)},
		"low diversity":      {bytes.Repeat([]byte("abcd"), kek.KeyLength/4)},
		"weak previous":      {good, make([]byte, kek.KeyLength)},
		"duplicate previous": {good, bytes.Clone(good)},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := kek.NewLocal(keys[0], keys[1:]...)
			if !errors.Is(err, kek.ErrInvalidKey) {
				t.Fatalf("NewLocal error = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestAADIsMandatory(t *testing.T) {
	ctx := context.Background()
	l := newLocal(t, randomKey(t))
	if _, err := l.Seal(ctx, []byte("secret"), nil); !errors.Is(err, kek.ErrAADRequired) {
		t.Fatalf("Seal(nil aad) = %v, want ErrAADRequired", err)
	}
	if _, err := l.Seal(ctx, []byte("secret"), kek.AAD{}); !errors.Is(err, kek.ErrAADRequired) {
		t.Fatalf("Seal(empty aad) = %v, want ErrAADRequired", err)
	}
	ct, err := l.Seal(ctx, []byte("secret"), kek.AAD("a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Open(ctx, ct, nil); !errors.Is(err, kek.ErrAADRequired) {
		t.Fatalf("Open(nil aad) = %v, want ErrAADRequired", err)
	}
}

func TestWrongAADFails(t *testing.T) {
	ctx := context.Background()
	l := newLocal(t, randomKey(t))
	ct, err := l.Seal(ctx, []byte("totp-seed"), kek.AAD("egauth/totp/v1\x00tenant-a\x00user-1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, aad := range []string{
		"egauth/totp/v1\x00tenant-b\x00user-1",
		"egauth/totp/v1\x00tenant-a\x00user-2",
		"egauth/totp/v1\x00tenant-a\x00user-1\x00",
	} {
		if _, err := l.Open(ctx, ct, kek.AAD(aad)); !errors.Is(err, kek.ErrOpenFailed) {
			t.Fatalf("Open under %q = %v, want ErrOpenFailed", aad, err)
		}
	}
}

func TestCiphertextFormat(t *testing.T) {
	ctx := context.Background()
	key := randomKey(t)
	l := newLocal(t, key)
	okm, err := hkdf.Key(sha256.New, key, nil, "egauth/kek-id", 32)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(okm)
	wantID := hex.EncodeToString(sum[:8])
	if got := l.CurrentKeyID(); got != wantID {
		t.Fatalf("CurrentKeyID = %q, want %q", got, wantID)
	}
	pt := []byte("plaintext")
	ct, err := l.Seal(ctx, pt, kek.AAD("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if ct[0] != 0x01 || int(ct[1]) != len(wantID) || string(ct[2:2+len(wantID)]) != wantID {
		t.Fatalf("header = %x, want 0x01 ‖ len ‖ %s", ct[:2+len(wantID)], wantID)
	}
	if want := 2 + len(wantID) + 12 + len(pt) + 16; len(ct) != want {
		t.Fatalf("len(ct) = %d, want %d (header ‖ nonce ‖ ct ‖ tag)", len(ct), want)
	}
	if id, err := l.KeyIDOf(ct); err != nil || id != wantID {
		t.Fatalf("KeyIDOf = %q, %v", id, err)
	}
}

func TestHeaderTamperFails(t *testing.T) {
	ctx := context.Background()
	l := newLocal(t, randomKey(t))
	ct, err := l.Seal(ctx, []byte("x"), kek.AAD("aad"))
	if err != nil {
		t.Fatal(err)
	}
	version := bytes.Clone(ct)
	version[0] = 0x02
	if _, err := l.Open(ctx, version, kek.AAD("aad")); !errors.Is(err, kek.ErrMalformed) {
		t.Fatalf("Open(version 2) = %v, want ErrMalformed", err)
	}
	if _, err := l.KeyIDOf(version); !errors.Is(err, kek.ErrMalformed) {
		t.Fatalf("KeyIDOf(version 2) = %v, want ErrMalformed", err)
	}
	kid := bytes.Clone(ct)
	kid[2] ^= 0x01
	if _, err := l.Open(ctx, kid, kek.AAD("aad")); !errors.Is(err, kek.ErrUnknownKey) {
		t.Fatalf("Open(kid flipped) = %v, want ErrUnknownKey", err)
	}
	for _, short := range [][]byte{nil, {0x01}, ct[:2], ct[:len(ct)-len("x")-17]} {
		if _, err := l.Open(ctx, short, kek.AAD("aad")); !errors.Is(err, kek.ErrMalformed) {
			t.Fatalf("Open(%x) = %v, want ErrMalformed", short, err)
		}
	}
}

func TestRotation(t *testing.T) {
	ctx := context.Background()
	oldKey, newKey := randomKey(t), randomKey(t)
	old := newLocal(t, oldKey)
	ct, err := old.Seal(ctx, []byte("data key"), kek.AAD("egauth/deployment/v1\x00datakey"))
	if err != nil {
		t.Fatal(err)
	}
	rotated := newLocal(t, newKey, oldKey)
	if rotated.CurrentKeyID() == old.CurrentKeyID() {
		t.Fatal("rotation kept the old key current")
	}
	pt, err := rotated.Open(ctx, ct, kek.AAD("egauth/deployment/v1\x00datakey"))
	if err != nil || string(pt) != "data key" {
		t.Fatalf("rotated Open = %q, %v", pt, err)
	}
	if id, _ := rotated.KeyIDOf(ct); id != old.CurrentKeyID() || id == rotated.CurrentKeyID() {
		t.Fatalf("KeyIDOf(old ct) = %q, want the old key id %q", id, old.CurrentKeyID())
	}
	fresh, err := rotated.Seal(ctx, pt, kek.AAD("egauth/deployment/v1\x00datakey"))
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := rotated.KeyIDOf(fresh); id != rotated.CurrentKeyID() {
		t.Fatalf("re-sealed under %q, want current %q", id, rotated.CurrentKeyID())
	}
	dropped := newLocal(t, newKey)
	if _, err := dropped.Open(ctx, ct, kek.AAD("egauth/deployment/v1\x00datakey")); !errors.Is(err, kek.ErrUnknownKey) {
		t.Fatalf("Open after dropping the old key = %v, want ErrUnknownKey", err)
	}
	if _, err := dropped.Open(ctx, fresh, kek.AAD("egauth/deployment/v1\x00datakey")); err != nil {
		t.Fatalf("re-sealed ciphertext does not open under the new key alone: %v", err)
	}
}

func TestConstructorsCopyKeyBytes(t *testing.T) {
	ctx := context.Background()
	key := randomKey(t)
	l := newLocal(t, key)
	ct, err := l.Seal(ctx, []byte("x"), kek.AAD("aad"))
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	if _, err := l.Open(ctx, ct, kek.AAD("aad")); err != nil {
		t.Fatalf("Open after the caller zeroed its key buffer: %v", err)
	}
}

func TestLocalIsRedacted(t *testing.T) {
	key := randomKey(t)
	l := newLocal(t, key)
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("kek", "k", l)
	out := fmt.Sprintf("%v %+v %#v %s", l, l, l, l) + buf.String()
	for _, leak := range []string{hex.EncodeToString(key), string(key)} {
		if strings.Contains(out, leak) {
			t.Fatalf("formatted KEK leaks key material: %s", out)
		}
	}
}

func TestCheckConformanceRejectsAADIgnoringKEK(t *testing.T) {
	err := kek.CheckConformance(context.Background(), ignoresAAD{newLocal(t, randomKey(t))})
	if !errors.Is(err, kek.ErrNonConforming) {
		t.Fatalf("CheckConformance = %v, want ErrNonConforming", err)
	}
	if err := kek.CheckConformance(context.Background(), nil); !errors.Is(err, kek.ErrNonConforming) {
		t.Fatalf("CheckConformance(nil) = %v, want ErrNonConforming", err)
	}
}

type ignoresAAD struct{ inner *kek.Local }

func (k ignoresAAD) Seal(ctx context.Context, pt []byte, _ kek.AAD) ([]byte, error) {
	return k.inner.Seal(ctx, pt, kek.AAD("fixed"))
}

func (k ignoresAAD) Open(ctx context.Context, ct []byte, _ kek.AAD) ([]byte, error) {
	return k.inner.Open(ctx, ct, kek.AAD("fixed"))
}

func (k ignoresAAD) CurrentKeyID() string { return k.inner.CurrentKeyID() }

func (k ignoresAAD) KeyIDOf(ct []byte) (string, error) { return k.inner.KeyIDOf(ct) }

type legacyFixtures struct {
	Key   string
	Cases []struct{ Name, AAD, Plaintext, Blob string }
}

func loadLegacy(t *testing.T) (key []byte, f legacyFixtures) {
	t.Helper()
	raw, err := os.ReadFile("testdata/v016_fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	key, err = hex.DecodeString(f.Key)
	if err != nil {
		t.Fatal(err)
	}
	return key, f
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLegacyOpenerOpensV016Fixtures(t *testing.T) {
	ctx := context.Background()
	key, f := loadLegacy(t)
	if len(f.Cases) == 0 {
		t.Fatal("no v0.16 fixtures")
	}
	legacy, err := kek.LegacyLocalV016(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			blob, aad, want := unhex(t, c.Blob), unhex(t, c.AAD), unhex(t, c.Plaintext)
			got, err := legacy.OpenLegacy(ctx, blob, kek.AAD(aad))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("OpenLegacy = %q, %v; want %q", got, err, want)
			}
			wrong := kek.AAD("not-the-legacy-aad")
			if _, err := legacy.OpenLegacy(ctx, blob, wrong); !errors.Is(err, kek.ErrOpenFailed) {
				t.Fatalf("OpenLegacy under a wrong AAD = %v, want ErrOpenFailed", err)
			}
		})
	}
}

func TestLegacyBlobIsNotAV1Ciphertext(t *testing.T) {
	ctx := context.Background()
	key, f := loadLegacy(t)
	l := newLocal(t, key)
	for _, c := range f.Cases {
		aad := unhex(t, c.AAD)
		if len(aad) == 0 {
			aad = []byte("x")
		}
		if _, err := l.Open(ctx, unhex(t, c.Blob), kek.AAD(aad)); err == nil {
			t.Fatalf("v1 Open accepted the v0.16 blob %q", c.Name)
		}
	}
}

func TestLegacyLocalV016RejectsBadKeys(t *testing.T) {
	for name, key := range map[string][]byte{
		"short":    make([]byte, 16),
		"all zero": make([]byte, kek.KeyLength),
	} {
		if _, err := kek.LegacyLocalV016(key); !errors.Is(err, kek.ErrInvalidKey) {
			t.Fatalf("%s: LegacyLocalV016 = %v, want ErrInvalidKey", name, err)
		}
	}
	if _, err := kek.LegacyLocalV016(randomKey(t)); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyOpenerRejectsShortBlob(t *testing.T) {
	legacy, err := kek.LegacyLocalV016(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.OpenLegacy(context.Background(), make([]byte, 27), nil); !errors.Is(err, kek.ErrMalformed) {
		t.Fatalf("OpenLegacy(short) = %v, want ErrMalformed", err)
	}
}
