package ceremonycodec_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/secretpolicy"
)

func TestNewSealerRejectsPublishedCredentials(t *testing.T) {
	checked := 0
	for denied := range secretpolicy.Denied {
		if len(denied) != ceremonycodec.DataKeyBytes {
			continue
		}
		checked++
		if _, err := ceremonycodec.NewSealer([]byte(denied), clock.Clock{}); !errors.Is(err, ceremonycodec.ErrInvalidDataKey) {
			t.Errorf("NewSealer(%q) = %v, want ErrInvalidDataKey", denied, err)
		}
	}
	if checked == 0 {
		t.Fatal("secretpolicy.Denied has no 32-byte entry; the check is vacuous")
	}
	if _, err := ceremonycodec.NewSealer([]byte("x-minimum-hs256-signing-secret-y"), clock.Clock{}); !errors.Is(err, ceremonycodec.ErrInvalidDataKey) {
		t.Errorf("NewSealer(near-copy) = %v, want ErrInvalidDataKey", err)
	}
}

func TestCodeDigestIsKeyedByTheDataKey(t *testing.T) {
	s := sealer(t, clock.NewTest(base).Clock())
	const code = "123456"
	b, err := ceremonycodec.SMSCode().Encode(mustCode(t, s, code))
	if err != nil {
		t.Fatal(err)
	}
	for _, unkeyed := range [][]byte{
		sha256Of("egauth/short-code/v1\x00" + code),
		sha256Of(code),
	} {
		if bytes.Contains(b, []byte(base64.RawURLEncoding.EncodeToString(unkeyed))) {
			t.Fatal("persisted code digest is an unkeyed hash: a 6-digit code is recovered with 10^6 hashes")
		}
	}
	other := sealer(t, clock.NewTest(base).Clock())
	if mustCode(t, s, code).Matches(other, code) {
		t.Fatal("a code keyed under one data key matches under another")
	}
	if mustCode(t, s, code).Matches(nil, code) {
		t.Fatal("a nil Sealer matches")
	}
	if _, err := ceremonycodec.NewCode(nil, code); !errors.Is(err, ceremonycodec.ErrMalformedPayload) {
		t.Fatalf("NewCode(nil sealer) = %v, want ErrMalformedPayload", err)
	}
}

func sha256Of(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
