package fake_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/othertest"
	foo "github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo/fake"
)

func TestSuite(t *testing.T) {
	othertest.Run(t, func(*testing.T) foo.Store { return &fake.Fake{} })
}
