package pgx

import "context"

type dummyKEK struct{}

func (dummyKEK) Seal(_ context.Context, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}
func (dummyKEK) Open(_ context.Context, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}
