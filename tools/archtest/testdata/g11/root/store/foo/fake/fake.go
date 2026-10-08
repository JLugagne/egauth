package fake

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo"
)

type Fake struct{}

func (*Fake) Ping(ctx context.Context) error { return nil }

func (*Fake) Get(ctx context.Context, id string) (string, error) { return "", nil }

var _ foo.Store = (*Fake)(nil)
