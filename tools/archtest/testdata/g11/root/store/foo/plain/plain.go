package plain

import "context"

type Plain struct{}

func (*Plain) Ping(ctx context.Context) error { return nil }

func (*Plain) Get(ctx context.Context, id string) (string, error) { return "", nil }

func New() *Plain { return &Plain{} }
