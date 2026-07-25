package pgx

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/mfa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// recordingKEK captures the SecretContext each call is given and seals by identity, so a test can
// pin the binding the store must supply without a database or a real cipher.
type recordingKEK struct {
	sealContexts []keystore.SecretContext
	openContexts []keystore.SecretContext
}

func (k *recordingKEK) Seal(sc keystore.SecretContext, plaintext []byte) ([]byte, error) {
	k.sealContexts = append(k.sealContexts, sc)
	return plaintext, nil
}

func (k *recordingKEK) Open(sc keystore.SecretContext, sealed []byte) ([]byte, error) {
	k.openContexts = append(k.openContexts, sc)
	return sealed, nil
}

// totpRow scans one mfa_totp row whose secret column holds the (base64 of the) sealed secret.
type totpRow struct{ secret string }

func (r totpRow) Scan(dest ...any) error {
	for i, d := range dest {
		switch p := d.(type) {
		case *string:
			*p = r.secret
		case **time.Time:
			*p = nil
		case *int64:
			*p = 0
		case *int:
			*p = 0
		case *time.Time:
			*p = time.Unix(1_700_000_000, 0).UTC()
		default:
			t := i
			_ = t
		}
	}
	return nil
}

type totpQuerier struct{ row totpRow }

func (q *totpQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (q *totpQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }
func (q *totpQuerier) QueryRow(context.Context, string, ...any) pgx.Row        { return q.row }

// TestTOTPSecretIsSealedWithItsRowContext pins the binding for the TOTP secret at rest: it must be
// sealed and opened under (tenant, mfa/totp-secret, user id), so a ciphertext lifted from another
// row, another tenant or another subsystem cannot be decrypted here.
func TestTOTPSecretIsSealedWithItsRowContext(t *testing.T) {
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV7())
	kek := &recordingKEK{}
	store := NewStore(&totpQuerier{row: totpRow{secret: base64.StdEncoding.EncodeToString([]byte("sealed"))}}, kek)

	if err := store.SaveTOTP(ctx, "acme", &mfa.TOTPEnrollment{UserID: uid, Secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}); err != nil {
		t.Fatalf("SaveTOTP: %v", err)
	}
	want := keystore.SecretContext{TenantID: "acme", Purpose: keystore.PurposeTOTPSecret, RowID: uid.String()}
	if len(kek.sealContexts) != 1 || kek.sealContexts[0] != want {
		t.Fatalf("SaveTOTP sealed with %+v, want %+v", kek.sealContexts, want)
	}

	if _, err := store.GetTOTP(ctx, "acme", uid); err != nil {
		t.Fatalf("GetTOTP: %v", err)
	}
	if len(kek.openContexts) != 1 || kek.openContexts[0] != want {
		t.Fatalf("GetTOTP opened with %+v, want %+v", kek.openContexts, want)
	}
}

// TestTOTPSecretContextIsExportedForReSealing keeps the operator migration path honest: the context
// a row is sealed under must be reproducible from outside the package.
func TestTOTPSecretContextIsExportedForReSealing(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	got := TOTPSecretContext("acme", uid)
	want := keystore.SecretContext{TenantID: "acme", Purpose: keystore.PurposeTOTPSecret, RowID: uid.String()}
	if got != want {
		t.Fatalf("TOTPSecretContext = %+v, want %+v", got, want)
	}
}
