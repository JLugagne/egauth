package plain_test

import (
	"testing"

	foo "github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo/plain"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo/storetest"
)

var _ foo.Store = (*plain.Plain)(nil)

func TestSuite(t *testing.T) {
	storetest.Run(t, func(*testing.T) foo.Store { return plain.New() })
}
