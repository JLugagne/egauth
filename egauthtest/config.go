package egauthtest

import (
	"crypto/rand"

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
// Read captured mail back with cfg.Email.(*egauthtest.Mailbox). Every call draws a fresh KEK from
// crypto/rand, so data sealed under one Config is unreadable under another: keep cfg.KEK to reopen
// a store. Every opt-out carries TestOptOutReason and is accepted by New only while every origin
// and audience is loopback; a public deployment must acknowledge it with its own reason.
func Config[C any]() egauth.Config[C] {
	k, _ := kek.NewLocal(randomKey())
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
			NoRateLimit: egauth.TestHookDevelopmentAck(TestOptOutReason),
		},
	}
}

func randomKey() []byte {
	key := make([]byte, kek.KeyLength)
	_, _ = rand.Read(key)
	return key
}
