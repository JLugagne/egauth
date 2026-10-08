package jwt_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/internal/session"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/internal/session/backendtest"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g11/root/internal/session/jwt"
)

func TestBackend(t *testing.T) {
	backendtest.Run(t, func(*testing.T) session.Backend { return &jwt.Jwt{} })
}
