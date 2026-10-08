package keytest

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/kek"
)

func Run(t *testing.T, newKEK func(*testing.T) kek.KEK) { _ = newKEK(t) }
