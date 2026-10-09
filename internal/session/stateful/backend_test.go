package stateful_test

import (
	"testing"

	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/backendtest"
)

func TestBackendSuite(t *testing.T) {
	backendtest.Run(t, func(t *testing.T) session.Backend {
		b := build(t, backendtest.NewFixture(t))
		return b
	})
}
