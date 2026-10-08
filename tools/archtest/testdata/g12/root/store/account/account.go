package account

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/store"
)

type Store interface {
	store.Base
	ListForAccount(ctx context.Context, tenant string, accountID [16]byte) ([]string, error)
}
