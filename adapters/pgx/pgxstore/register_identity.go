package pgxstore

import "github.com/JLugagne/egauth/adapters/pgx/internal/migrate"

func moduleIdentity() migrate.Module { return migrate.Module{Name: "identity"} }
