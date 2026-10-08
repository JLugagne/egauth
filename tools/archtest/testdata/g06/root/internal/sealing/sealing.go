package sealing

import "github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/kek"

type sealer interface {
	Seal(p []byte) ([]byte, error)
}

func Seal(k kek.KEK, l *kek.Local) {
	_, _ = k.Seal(nil)
	_, _ = l.Open(nil)
	var s sealer = k
	_, _ = s.Seal(nil)
}
