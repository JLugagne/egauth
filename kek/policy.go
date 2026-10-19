package kek

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strconv"
)

const minDistinct = 8

var publishedKeys = map[string]bool{
	"replace-with-a-32-byte-minimum-secret-in-production!": true,
	"super-secret-32-byte-key-here!!!":                     true,
	"a-high-entropy-secret-kept-out-of-source-control":     true,
	"super-secret-key-change-me-in-production":             true,
	"a-32-byte-minimum-hs256-signing-secret!!":             true,
	"very-secure-32-byte-secret-key!!":                     true,
	"kek-fixture-0123456789abcdefghij":                     true,
}

var committedKeys = map[string]bool{
	"f09ac7b6cd027f80845be0a80d7e630f397dd301d4c883233d1eae95a02d1d57": true,
	"8721a837f508549ef011da2bcd23828d631c2b4f90cd28df3e45aef15344f330": true,
	"eae742403e28066311c48d555ae1c2657f15e5f1c7459aba87abe1c626389c0e": true,
	"130546ee34877be01b76a4fa208e33aa7bf535fedc51a11191b09e8b99618f20": true,
	"72bdc7164df1e5a5728f6779fef377eefdcd8563c3631557eadfbc134f1db230": true,
	"3751339ea50726222c92091f660d088033581afae80c89f3b6d448f49c8ac9f6": true,
	"29d431921b20436542c65645d4f13100d11d6491a5909b020a95ea54148635a8": true,
	"bbc9e5cdbdc21a35d4960524b4af0714b8839389f84ef1015345886054eb7a4b": true,
	"c3469082c7824464836825027036f4b02716fd8f0e762f6655a2e191a60b5bdf": true,
	"86642898dd030295e132b7f67980d945562bcd767cd50efc408ef12b8684f478": true,
	"4a425357593344504548504b335058504a425357593344504548504b33505850": true,
	"02507154933166867c21b0da53f65f95b8cdc9434a1b51a173f1a2a69a95968e": true,
	"1cab18f6c032b810ff7cfbd713b7889bdfd960a6889b09adb312627e96353aeb": true,
	"a3ed98077850c0aa0933937b797977a8efd606948a045fe22735232fd9884685": true,
	"f4c82ee01d7f60e407f586442870fe6d57f2347771f31cc5cec2d8007d76d39d": true,
}

var publishedMarkers = []string{
	"minimum-hs256-signing-secret",
}

func checkKey(key []byte) error {
	if err := checkLegacyKey(key); err != nil {
		return err
	}
	if distinctBytes(key) < minDistinct {
		return errors.New("key is trivially guessable; generate it with crypto/rand")
	}
	if committedKeys[hex.EncodeToString(key)] {
		return errors.New("key is committed to egauth's public repository; generate it with crypto/rand")
	}
	return nil
}

func checkLegacyKey(key []byte) error {
	if len(key) != KeyLength {
		return errors.New("key must be exactly " + strconv.Itoa(KeyLength) + " bytes")
	}
	if distinctBytes(key) < 2 {
		return errors.New("key is trivially guessable (all-zero or a single repeated byte)")
	}
	if published(key) {
		return errors.New("key is a credential published in egauth's examples or docs; generate it with crypto/rand")
	}
	return nil
}

func published(key []byte) bool {
	if publishedKeys[string(key)] {
		return true
	}
	for _, m := range publishedMarkers {
		if bytes.Contains(key, []byte(m)) {
			return true
		}
	}
	return false
}

func distinctBytes(key []byte) int {
	var seen [256]bool
	n := 0
	for _, b := range key {
		if !seen[b] {
			seen[b] = true
			n++
		}
	}
	return n
}
