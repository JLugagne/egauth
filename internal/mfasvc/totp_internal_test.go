package mfasvc

import (
	"testing"
	"time"
)

func TestHOTPMatchesRFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"}
	for at, want := range cases {
		if got := hotp(key, uint64(at/totpPeriod)); got != want {
			t.Fatalf("T=%d: got %s want %s", at, got, want)
		}
		step, ok := matchTOTP(key, want, time.Unix(at, 0))
		if !ok || step != at/totpPeriod {
			t.Fatalf("T=%d: match = %d, %v", at, step, ok)
		}
	}
}

func TestMatchTOTPWindow(t *testing.T) {
	key := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	step := now.Unix() / totpPeriod
	for _, d := range []int64{-1, 0, 1} {
		if _, ok := matchTOTP(key, hotp(key, uint64(step+d)), now); !ok {
			t.Fatalf("offset %d refused", d)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := matchTOTP(key, hotp(key, uint64(step+d)), now); ok {
			t.Fatalf("offset %d accepted", d)
		}
	}
}

func TestWellFormedTOTP(t *testing.T) {
	for _, c := range []string{"123456", "000000"} {
		if !wellFormedTOTP(c) {
			t.Fatalf("%q refused", c)
		}
	}
	for _, c := range []string{"", "12345", "1234567", "12345a", "١٢٣٤٥٦", "12 456"} {
		if wellFormedTOTP(c) {
			t.Fatalf("%q accepted", c)
		}
	}
}
