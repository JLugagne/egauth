package pgxstore

import (
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	limiterstore "github.com/JLugagne/egauth/adapters/pgx/store/limiter"
)

func moduleLimiter() migrate.Module {
	return migrate.Module{Name: "limiter", FS: limiterstore.Migrations}
}
