package pgxstore

import (
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	identitystore "github.com/JLugagne/egauth/adapters/pgx/store/identity"
)

func moduleIdentity() migrate.Module {
	return migrate.Module{Name: "identity", FS: identitystore.Migrations}
}
