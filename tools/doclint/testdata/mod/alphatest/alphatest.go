// Package alphatest is a fixture suite package.
package alphatest

import "testing"

// Run is a fixture suite.
func Run(t *testing.T) {}

// RunTB is a fixture suite taking testing.TB.
func RunTB(tb testing.TB, n int) {}

// Helper is not a suite.
func Helper(n int) {}

// Suite is a fixture suite type.
type Suite struct{}

// Run is a fixture suite method.
func (Suite) Run(t *testing.T) {}

// Fake is a fixture helper type.
type Fake struct{}

// NewFake is a helper factory, not a suite.
func NewFake(t *testing.T) *Fake { return &Fake{} }
