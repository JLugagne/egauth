package pgxstore

import (
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	deploymentstore "github.com/JLugagne/egauth/adapters/pgx/store/deployment"
)

func moduleDeployment() migrate.Module {
	return migrate.Module{Name: "deployment", FS: deploymentstore.Migrations}
}
