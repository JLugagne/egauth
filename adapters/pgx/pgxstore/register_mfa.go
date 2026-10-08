package pgxstore

import (
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	mfastore "github.com/JLugagne/egauth/adapters/pgx/store/mfa"
)

func moduleMFA() migrate.Module { return migrate.Module{Name: "mfa", FS: mfastore.Migrations} }
