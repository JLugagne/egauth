// Package pgxstore wires the pgx-backed stores and their schema modules. A module name is the key of
// its rows in egauth_schema_migrations and never changes. The key store module is named "keys"; it is
// the module DESIGN §4.9 lists as keystore, and its migrations (003_kek_v1.sql onward) register
// under "keys".
package pgxstore

import "github.com/JLugagne/egauth/adapters/pgx/internal/migrate"

func modules() []migrate.Module {
	return []migrate.Module{
		moduleCeremony(),
		moduleDeployment(),
		moduleLimiter(),
		moduleIdentity(),
		moduleTokens(),
		moduleSessions(),
		moduleMFA(),
		modulePasskey(),
		moduleFederation(),
		moduleKeys(),
	}
}
