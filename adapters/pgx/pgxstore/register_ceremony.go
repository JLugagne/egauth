package pgxstore

import (
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	ceremonystore "github.com/JLugagne/egauth/adapters/pgx/store/ceremony"
)

func moduleCeremony() migrate.Module {
	return migrate.Module{Name: "ceremony", FS: ceremonystore.Migrations}
}
