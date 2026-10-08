package sessions

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g08/root/ext"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g08/root/principal"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g08/root/store"
)

type Draft struct{ ID string }

type Keyed struct{ ID string }

type Echo struct{ ID string }

type Compound interface {
	GetOrCreate(ctx context.Context, d Draft) (Draft, error)
	LoadOrStore(ctx context.Context, k Keyed) error
	GetEcho(ctx context.Context, e Echo) (Echo, error)
	StartRaw(ctx context.Context, hash []byte, amr []string, attrs []byte) error
	Import(ctx context.Context, r ext.Row) error
	RevocationsSince(ctx context.Context, c store.Cursor) error
	RevokeForSubject(ctx context.Context, s principal.Subject, except [16]byte) error
	Revoke(ctx context.Context, hash []byte) error
}
