package egauthtest_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/memstore"
)

func TestConfigOptOutsAreRefusedOffLoopback(t *testing.T) {
	cfg := egauthtest.Config[struct{}]()
	cfg.PublicOrigin = "https://auth.example.com"
	cfg.Storage = memstore.New(cfg.KEK)
	cfg.Insecure.EphemeralState = egauth.Acknowledge("single replica demo")
	a, err := egauth.New(cfg)
	if err == nil {
		_ = a.Close()
	}
	require.Error(t, err, "the egauthtest opt-outs must not reach a deployment on a public origin")
	require.Contains(t, err.Error(), "Insecure.NoRateLimit")
}

func TestConfigOptOutsCannotBeReplayedByAPlainAcknowledge(t *testing.T) {
	cfg := egauthtest.Config[struct{}]()
	cfg.PublicOrigin = "https://auth.example.com"
	cfg.Storage = memstore.New(cfg.KEK)
	cfg.Insecure.EphemeralState = egauth.Acknowledge("single replica demo")
	cfg.Insecure.NoRateLimit = egauth.Acknowledge("rate limited by the gateway")
	a, err := egauth.New(cfg)
	require.NoError(t, err, "an operator's own acknowledgement stays legitimate in production")
	t.Cleanup(func() { _ = a.Close() })
}

func TestConfigKEKIsFreshOnEveryCall(t *testing.T) {
	a, b := egauthtest.Config[struct{}](), egauthtest.Config[struct{}]()
	require.NotEqual(t, a.KEK.CurrentKeyID(), b.KEK.CurrentKeyID(), "a KEK shared by every Config is derivable by anyone reading the source")
}
