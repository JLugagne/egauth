package pgxstore

import "github.com/JLugagne/egauth/adapters/pgx/internal/migrate"

func moduleDeployment() migrate.Module { return migrate.Module{Name: "deployment"} }
