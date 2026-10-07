package pgxstore

import "github.com/JLugagne/egauth/adapters/pgx/internal/migrate"

func modulePasskey() migrate.Module { return migrate.Module{Name: "passkey"} }
