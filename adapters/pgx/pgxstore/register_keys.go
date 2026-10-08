package pgxstore

import (
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	keysstore "github.com/JLugagne/egauth/adapters/pgx/store/keys"
)

func moduleKeys() migrate.Module {
	return migrate.Module{Name: "keys", FS: keysstore.Migrations}
}
