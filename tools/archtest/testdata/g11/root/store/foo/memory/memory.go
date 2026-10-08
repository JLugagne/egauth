package memory

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/store/foo"
)

type Memory struct{}

func (*Memory) Ping(ctx context.Context) error { return nil }

func (*Memory) Get(ctx context.Context, id string) (string, error) { return "", nil }

func New() *Memory { return &Memory{} }

var _ foo.Store = (*Memory)(nil)
