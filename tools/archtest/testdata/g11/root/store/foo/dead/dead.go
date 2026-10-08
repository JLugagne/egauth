package dead

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo"
)

type Dead struct{}

func (*Dead) Ping(ctx context.Context) error { return nil }

func (*Dead) Get(ctx context.Context, id string) (string, error) { return "", nil }

func New() *Dead { return &Dead{} }

var _ foo.Store = (*Dead)(nil)
