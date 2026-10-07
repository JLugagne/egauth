package pgxstore

import "github.com/JLugagne/egauth/adapters/pgx/internal/migrate"

func moduleKeys() migrate.Module { return migrate.Module{Name: "keys"} }
