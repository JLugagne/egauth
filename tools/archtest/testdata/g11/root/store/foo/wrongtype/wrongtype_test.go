package wrongtype_test

import (
	"testing"

	foo "github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo/storetest"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo/wrongtype"
)

func TestSuite(t *testing.T) {
	storetest.Run(t, func(*testing.T) foo.Store { return wrongtype.NewStore() })
}
