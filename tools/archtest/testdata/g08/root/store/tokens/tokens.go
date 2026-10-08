package tokens

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g08/root/principal"
)

type RefreshRecord struct {
	ID    string
	Attrs principal.Sealed
}

type BadRecord struct{ ID string }

type APIKey struct{ ID string }

type Filter struct{ Limit int }

type RotationRequest struct {
	Old  []byte
	Next RefreshRecord
}

type ReissueRequest struct {
	Old  []byte
	Next BadRecord
}

type Store interface {
	Shapes
	Create(ctx context.Context, r RefreshRecord) error
	Put(ctx context.Context, r *BadRecord) error
	SaveKey(ctx context.Context, k APIKey) error
	List(ctx context.Context, f Filter) ([]RefreshRecord, error)
	LookupFamily(ctx context.Context, f Filter) ([]RefreshRecord, error)
	ConsumeForRotation(ctx context.Context, req RotationRequest) error
	Reissue(ctx context.Context, req ReissueRequest) error
}
