package kek

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestLegacyBlobIsNotAV1CiphertextUnderTheSameKey(t *testing.T) {
	raw, err := os.ReadFile("testdata/v016_fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Key   string
		Cases []struct {
			Name, AAD, Blob string
		}
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(f.Key)
	if err != nil {
		t.Fatal(err)
	}
	k, err := deriveLocalKey(key)
	if err != nil {
		t.Fatal(err)
	}
	l := &Local{current: k, byID: map[string]*localKey{k.id: k}}
	for _, c := range f.Cases {
		aad, _ := hex.DecodeString(c.AAD)
		if len(aad) == 0 {
			aad = []byte("x")
		}
		blob, err := hex.DecodeString(c.Blob)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.Open(context.Background(), blob, AAD(aad)); err == nil {
			t.Fatalf("v1 Open accepted the v0.16 blob %q", c.Name)
		}
	}
}
