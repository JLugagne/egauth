package local

type Local struct{}

func (*Local) Seal(p []byte) ([]byte, error) { return p, nil }

func (*Local) Open(p []byte) ([]byte, error) { return p, nil }
