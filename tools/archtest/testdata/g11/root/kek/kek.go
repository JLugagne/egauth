package kek

type KEK interface {
	Seal(p []byte) ([]byte, error)
	Open(p []byte) ([]byte, error)
}
