package wrongtype

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo"
)

type Wrongtype struct{}

func (*Wrongtype) Ping(ctx context.Context) error { return nil }

func (*Wrongtype) Get(ctx context.Context, id string) (string, error) { return "", nil }

func New() *Wrongtype { return &Wrongtype{} }

var _ foo.Store = (*Wrongtype)(nil)

func NewStore() foo.Store { return New() }
