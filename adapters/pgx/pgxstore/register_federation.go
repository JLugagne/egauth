package pgxstore

import "github.com/JLugagne/egauth/adapters/pgx/internal/migrate"

func moduleFederation() migrate.Module { return migrate.Module{Name: "federation"} }
