package pgxstore

import (
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	tokensstore "github.com/JLugagne/egauth/adapters/pgx/store/tokens"
)

func moduleTokens() migrate.Module {
	return migrate.Module{Name: "tokens", FS: tokensstore.Migrations}
}
