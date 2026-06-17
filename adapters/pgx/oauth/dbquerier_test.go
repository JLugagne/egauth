package pgx

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Compile-time proof that the widened contract is additive-compatible: the concrete
// *pgxpool.Pool that existing callers pass still satisfies DBQuerier, and a pgx.Tx now does
// too (so a caller can run NewStore/Migrate inside a transaction, like every other pgx store).
var (
	_ DBQuerier = (*pgxpool.Pool)(nil)
	_ DBQuerier = pgx.Tx(nil)
)

// stubQuerier is a minimal DBQuerier (no live database) used to prove NewStore accepts any
// DBQuerier, not just a concrete pool.
type stubQuerier struct{}

func (stubQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (stubQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }
func (stubQuerier) QueryRow(context.Context, string, ...any) pgx.Row        { return nil }

// TestNewStoreAcceptsDBQuerier proves the constructor takes the widened DBQuerier interface
// (here a stub; in practice a *pgxpool.Pool or a pgx.Tx) rather than a concrete *pgxpool.Pool.
func TestNewStoreAcceptsDBQuerier(t *testing.T) {
	if s := NewStore(stubQuerier{}, dummyKEK{}, WithIssuerAllowlist([]string{"https://idp.example.com"})); s == nil {
		t.Fatal("NewStore returned nil for a non-pool DBQuerier")
	}
}
