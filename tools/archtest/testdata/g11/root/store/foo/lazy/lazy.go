package lazy

import "context"

type Lazy struct{}

func (*Lazy) Ping(ctx context.Context) error { return nil }

func (*Lazy) Get(ctx context.Context, id string) (string, error) { return "", nil }

func New() *Lazy { return &Lazy{} }
