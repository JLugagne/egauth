package pgxstore

import "github.com/JLugagne/egauth/adapters/pgx/internal/migrate"

func moduleCeremony() migrate.Module { return migrate.Module{Name: "ceremony"} }
