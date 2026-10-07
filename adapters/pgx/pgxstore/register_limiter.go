package pgxstore

import "github.com/JLugagne/egauth/adapters/pgx/internal/migrate"

func moduleLimiter() migrate.Module { return migrate.Module{Name: "limiter"} }
