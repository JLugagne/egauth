// Package core is a fixture depending on a module it does not load.
package core

import (
	"example.com/dep/pgx"
	"example.com/dep/protocol"
)

// Mode mirrors the dependency.
const Mode = protocol.VerificationRequired

// Tx mirrors the dependency.
type Tx = pgx.Tx
