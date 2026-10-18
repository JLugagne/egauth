package offline_test

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/passwords/breach/offline"
)

var errRead = errors.New("disk gone")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errRead }

func TestLoadErrorsKeepTheirCause(t *testing.T) {
	_, err := offline.LoadHashes(strings.NewReader(strings.Repeat("A", 40) + ":many\n"))
	if !errors.Is(err, strconv.ErrSyntax) {
		t.Errorf("malformed count: %v does not wrap strconv.ErrSyntax", err)
	}
	_, err = offline.LoadHashes(strings.NewReader(strings.Repeat("Z", 40) + "\n"))
	if _, ok := errors.AsType[hex.InvalidByteError](err); !ok {
		t.Errorf("invalid hash: %v does not wrap hex.InvalidByteError", err)
	}
	if _, err := offline.LoadHashes(failingReader{}); !errors.Is(err, errRead) {
		t.Errorf("LoadHashes read failure: %v does not wrap the reader error", err)
	}
	if _, err := offline.LoadPasswords(failingReader{}); !errors.Is(err, errRead) {
		t.Errorf("LoadPasswords read failure: %v does not wrap the reader error", err)
	}
}
