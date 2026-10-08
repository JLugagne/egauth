package sessions

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g08/root/principal"
)

type Record struct {
	ID    string
	Attrs principal.Sealed
}

type TouchRequest struct {
	Hash  []byte
	Attrs []byte
}

type Snapshot struct{ ID string }

type Store interface {
	Compound
	Create(ctx context.Context, r Record) error
	Get(ctx context.Context, id string) (Record, error)
	Touch(ctx context.Context, req TouchRequest) error
	Persist(ctx context.Context, s Snapshot) error
}
