package backendtest

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/internal/session"
)

func Run(t *testing.T, newBackend func(*testing.T) session.Backend) { _ = newBackend(t) }
