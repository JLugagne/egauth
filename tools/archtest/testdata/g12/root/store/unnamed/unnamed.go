package unnamed

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/store"
)

type Store interface {
	store.Base
	List(context.Context, string, [16]byte) ([]string, error)
}
