package norun

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo"
)

type Norun struct{}

func (*Norun) Ping(ctx context.Context) error { return nil }

func (*Norun) Get(ctx context.Context, id string) (string, error) { return "", nil }

func New() *Norun { return &Norun{} }

var _ foo.Store = (*Norun)(nil)
