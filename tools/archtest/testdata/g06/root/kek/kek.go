package kek

type KEK interface {
	Seal(p []byte) ([]byte, error)
	Open(p []byte) ([]byte, error)
}

type Local struct{}

func (l *Local) Seal(p []byte) ([]byte, error) { return l.Open(p) }

func (l *Local) Open(p []byte) ([]byte, error) { return p, nil }

func NewLocal() *Local { return &Local{} }
