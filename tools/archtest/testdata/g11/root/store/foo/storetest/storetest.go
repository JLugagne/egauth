package storetest

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo"
)

func Run(t *testing.T, newStore func(*testing.T) foo.Store) { _ = newStore(t) }
