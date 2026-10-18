package codesvc

import (
	"context"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/delivery"
	"github.com/JLugagne/egauth/internal/httpx"
)

type workers struct {
	pool *delivery.Pool
}

func newWorkers(a httpx.Audit) *workers { return &workers{pool: delivery.New(a)} }

func (w *workers) enqueue(ctx context.Context, t core.TenantID, run func(context.Context, uuid.UUID) error) {
	id := uuid.New()
	w.pool.Enqueue(ctx, t, id, func(c context.Context) error { return run(c, id) })
}

func (w *workers) close() { w.pool.Close() }
