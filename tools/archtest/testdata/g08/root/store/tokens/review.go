package tokens

import (
	"context"
	"time"
)

type Wrapper struct {
	Next      RefreshRecord
	RawAttrs  []byte
	Assurance int
	Methods   []string
}

type ScalarWrapper struct {
	Next      RefreshRecord
	Assurance int
}

type DatedWrapper struct {
	Old  []byte
	At   time.Time
	Next RefreshRecord
}

type Ensured struct{ ID string }

type Shapes interface {
	Rotate(ctx context.Context, w Wrapper) error
	RotateScalar(ctx context.Context, w ScalarWrapper) error
	RotateDated(ctx context.Context, w DatedWrapper) error
	GetEnsure(ctx context.Context, e Ensured) error
	ListAppend(ctx context.Context, methods []string) error
	FetchStamp(ctx context.Context, f Filter) (int, error)
}
