package pgxstore

import "github.com/JLugagne/egauth/adapters/pgx/internal/migrate"

func moduleTokens() migrate.Module { return migrate.Module{Name: "tokens"} }
