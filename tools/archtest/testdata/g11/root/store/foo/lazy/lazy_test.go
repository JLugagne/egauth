package lazy_test

import (
	"testing"

	foo "github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo/lazy"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo/storetest"
)

func TestSuite(t *testing.T) {
	storetest.Run(t, func(*testing.T) foo.Store { return lazy.New() })
}
