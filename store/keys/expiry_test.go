package keys_test

import (
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/store/keys"
)

func TestZeroExpiryIsInvalid(t *testing.T) {
	var zero keys.Expiry
	if zero.Valid() {
		t.Fatal("the zero Expiry must be invalid (X-16)")
	}
	if _, err := zero.At(time.Unix(0, 0), time.Hour); !errors.Is(err, keys.ErrInvalidExpiry) {
		t.Fatalf("zero Expiry resolved: %v", err)
	}
}

func TestExpireAfterRejectsNegative(t *testing.T) {
	if _, err := keys.ExpireAfter(-time.Second); !errors.Is(err, keys.ErrInvalidExpiry) {
		t.Fatalf("negative duration accepted: %v", err)
	}
}

func TestExpiryResolution(t *testing.T) {
	now := time.Unix(1000, 0)
	after, err := keys.ExpireAfter(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		e    keys.Expiry
		want time.Time
	}{
		{"after", after, now.Add(time.Hour)},
		{"never", keys.NeverExpire(), time.Time{}},
		{"default", keys.DefaultExpiry(), now.Add(24 * time.Hour)},
	}
	for _, c := range cases {
		if !c.e.Valid() {
			t.Fatalf("%s: not valid", c.name)
		}
		got, err := c.e.At(now, 24*time.Hour)
		if err != nil || !got.Equal(c.want) {
			t.Fatalf("%s: got %v, %v want %v", c.name, got, err, c.want)
		}
	}
	if !keys.NeverExpire().IsNever() || keys.DefaultExpiry().IsNever() {
		t.Fatal("IsNever mismatch")
	}
	if _, err := keys.DefaultExpiry().At(now, -time.Second); !errors.Is(err, keys.ErrInvalidExpiry) {
		t.Fatalf("negative fallback accepted: %v", err)
	}
}

func TestKeyActivity(t *testing.T) {
	now := time.Unix(1000, 0)
	retired := now
	cases := []struct {
		name    string
		k       keys.Key
		active  bool
		expired bool
	}{
		{"fresh", keys.Key{}, true, false},
		{"retired", keys.Key{RetiredAt: &retired}, false, false},
		{"past", keys.Key{NotAfter: now}, false, true},
		{"future", keys.Key{NotAfter: now.Add(time.Second)}, true, false},
	}
	for _, c := range cases {
		if c.k.IsActive(now) != c.active || c.k.IsExpired(now) != c.expired {
			t.Fatalf("%s: wrong activity", c.name)
		}
	}
}

func TestNeverExpireOverlapIsRefused(t *testing.T) {
	at := time.Unix(1000, 0)
	if _, err := keys.NeverExpire().OverlapUntil(at, time.Hour); !errors.Is(err, keys.ErrUnboundedOverlap) {
		t.Fatalf("a NeverExpire overlap must be refused, not resolved to the zero time: %v", err)
	}
	var zero keys.Expiry
	if _, err := zero.OverlapUntil(at, time.Hour); !errors.Is(err, keys.ErrInvalidExpiry) {
		t.Fatalf("zero overlap resolved: %v", err)
	}
	if _, err := keys.DefaultExpiry().OverlapUntil(at, 0); !errors.Is(err, keys.ErrInvalidExpiry) {
		t.Fatalf("a default overlap without a positive fallback resolved: %v", err)
	}
	after, err := keys.ExpireAfter(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string]keys.Expiry{"after": after, "default": keys.DefaultExpiry()} {
		until, err := e.OverlapUntil(at, time.Minute)
		if err != nil || !until.Equal(at.Add(time.Minute)) {
			t.Fatalf("%s: got %v, %v", name, until, err)
		}
		r := keys.Rotation{Previous: "k1", Next: keys.Key{KeyID: "k2", AADVersion: keys.AADVersionCurrent}, RetiredAt: at, OverlapUntil: until}
		if !r.Valid() {
			t.Fatalf("%s: a resolved overlap must make a valid Rotation", name)
		}
	}
}
