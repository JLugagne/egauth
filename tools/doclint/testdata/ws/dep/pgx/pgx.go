// Package pgx is a dependency-only fixture whose name a core package shares.
package pgx

// Tx is a fixture type.
type Tx struct{}

// Commit is a fixture method.
func (Tx) Commit() error { return nil }
