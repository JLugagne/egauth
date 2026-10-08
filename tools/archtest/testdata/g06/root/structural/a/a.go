package a

type Sealer interface {
	Seal(p []byte) ([]byte, error)
}

type sealing interface {
	Seal(p []byte) ([]byte, error)
}

func Do(s Sealer) { _, _ = s.Seal(nil) }

func DoGeneric[S sealing](s S) { _, _ = s.Seal(nil) }
