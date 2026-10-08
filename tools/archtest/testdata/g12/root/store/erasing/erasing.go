package erasing

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/principal"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/store"
)

type Store interface {
	store.Base
	ListFor(ctx context.Context, s principal.Subject) ([]string, error)
	DeleteForSubject(ctx context.Context, s principal.Subject) error
}
