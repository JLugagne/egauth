package pgxstore

import (
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	sessionsstore "github.com/JLugagne/egauth/adapters/pgx/store/sessions"
)

func moduleSessions() migrate.Module {
	return migrate.Module{Name: "sessions", FS: sessionsstore.Migrations}
}
