package pgxstore

import "github.com/JLugagne/egauth/adapters/pgx/internal/migrate"

func moduleMFA() migrate.Module { return migrate.Module{Name: "mfa"} }
