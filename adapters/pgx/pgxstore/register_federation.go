package pgxstore

import (
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	federationstore "github.com/JLugagne/egauth/adapters/pgx/store/federation"
)

func moduleFederation() migrate.Module {
	return migrate.Module{Name: "federation", FS: federationstore.Migrations}
}
