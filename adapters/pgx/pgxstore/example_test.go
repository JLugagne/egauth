package pgxstore_test

import (
	"context"
	"encoding/hex"
	"errors"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/adapters/pgx/pgxstore"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/signing"
)

func ExampleNew_postgres() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	if err := pgxstore.Migrate(ctx, pool); err != nil {
		log.Fatal(err)
	}
	storage, err := pgxstore.New(ctx, pool)
	if err != nil {
		log.Fatal(err)
	}

	auth, err := egauth.New(egauth.Config[struct{}]{
		PublicOrigin: "https://auth.example.com",
		Proxy:        egauth.DirectClients(),
		Storage:      storage,
		KEK:          kekFromEnv("EGAUTH_KEK"),
		Sessions:     egauth.JWT(egauth.StaticKeys(signerFromEnv("EGAUTH_SIGNING_SEED"))),
		Admin:        egauth.RoleAdmin("admin"),
		Email:        mailer{},
		Pages:        egauth.Pages{Login: "/login", AfterLogin: "/", ConfirmRegistration: "/confirm", PasswordReset: "/reset", SecurityRevert: "/revert"},
		Modules:      egauth.Modules{Password: &egauth.PasswordModule{}},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = auth.Close() }()
}

type mailer struct{}

func (mailer) send(context.Context, string, string) error {
	return errors.New("example: wire your email provider here")
}

func (m mailer) RegistrationLink(ctx context.Context, msg egauth.LinkMessage) error {
	return m.send(ctx, msg.To, msg.Link)
}
func (m mailer) AccountExistsNotice(ctx context.Context, msg egauth.NoticeMessage) error {
	return m.send(ctx, msg.To, "an account already exists for this address")
}
func (m mailer) PasswordResetLink(ctx context.Context, msg egauth.LinkMessage) error {
	return m.send(ctx, msg.To, msg.Link)
}
func (m mailer) MagicLink(ctx context.Context, msg egauth.LinkMessage) error {
	return m.send(ctx, msg.To, msg.Link)
}
func (m mailer) LoginCode(ctx context.Context, msg egauth.CodeMessage) error {
	return m.send(ctx, msg.To, msg.Code)
}
func (m mailer) EmailVerificationLink(ctx context.Context, msg egauth.LinkMessage) error {
	return m.send(ctx, msg.To, msg.Link)
}
func (m mailer) EmailChangeLink(ctx context.Context, msg egauth.LinkMessage) error {
	return m.send(ctx, msg.To, msg.Link)
}
func (m mailer) RecoveryEmailLink(ctx context.Context, msg egauth.LinkMessage) error {
	return m.send(ctx, msg.To, msg.Link)
}
func (m mailer) SecurityNotice(ctx context.Context, msg egauth.SecurityNoticeMessage) error {
	return m.send(ctx, msg.To, msg.Summary+"\n"+msg.RevertLink)
}

func keyFromEnv(name string) []byte {
	key, err := hex.DecodeString(os.Getenv(name))
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func kekFromEnv(name string) kek.KEK {
	k, err := kek.NewLocal(keyFromEnv(name))
	if err != nil {
		log.Fatal(err)
	}
	return k
}

func signerFromEnv(name string) signing.Signer {
	s, err := signing.EdDSA("k1", keyFromEnv(name))
	if err != nil {
		log.Fatal(err)
	}
	return s
}
