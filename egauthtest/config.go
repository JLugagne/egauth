package egauthtest

import (
	"crypto/sha256"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/kek"
)

// TestOptOutReason is the reason every opt-out of Config acknowledges; Posture reports it.
const TestOptOutReason = "egauthtest development configuration; never use in production"

// Config returns a loopback development configuration: stateful sessions, the password module with
// a Mailbox as Email, and the opt-outs a fast test needs (no rate limit). Storage is left empty
// because this package cannot import the stores; assign it before New:
//
//	cfg := egauthtest.Config[struct{}]()
//	cfg.Storage = memstore.New(cfg.KEK)
//
// Read captured mail back with cfg.Email.(*egauthtest.Mailbox). The KEK derives from a fixed public string, so it protects nothing. Every opt-out carries
// TestOptOutReason, and egauthtest is importable from test files only, which keeps them out of
// production code.
func Config[C any]() egauth.Config[C] {
	sum := sha256.Sum256([]byte("egauthtest development kek, public and worthless"))
	k, _ := kek.NewLocal(sum[:])
	return egauth.Config[C]{
		PublicOrigin: "http://localhost:8080",
		Proxy:        egauth.DirectClients(),
		KEK:          k,
		Sessions:     egauth.Stateful(),
		Admin:        egauth.RoleAdmin("admin"),
		Email:        &Mailbox{},
		Pages: egauth.Pages{
			Login:               "/login",
			ConfirmRegistration: "/register/confirm",
			PasswordReset:       "/reset",
			SecurityRevert:      "/revert",
		},
		Modules: egauth.Modules{Password: &egauth.PasswordModule{}},
		Insecure: egauth.InsecureOptOuts{
			NoRateLimit: egauth.Acknowledge(TestOptOutReason),
		},
	}
}
