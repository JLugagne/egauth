package pgx

import (
	"context"

	"github.com/JLugagne/egauth/keystore"
)

type dummyKEK struct{}

func (dummyKEK) Seal(_ context.Context, _ keystore.SecretContext, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}
func (dummyKEK) Open(_ context.Context, _ keystore.SecretContext, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}
