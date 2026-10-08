package pgxstore

import (
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	passkeystore "github.com/JLugagne/egauth/adapters/pgx/store/passkey"
)

func modulePasskey() migrate.Module {
	return migrate.Module{Name: "passkey", FS: passkeystore.Migrations}
}
