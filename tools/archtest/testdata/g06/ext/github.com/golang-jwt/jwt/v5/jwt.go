package jwt

func Parse(s string) string { return s }

type SigningMethod interface {
	Sign(signingString string, key any) ([]byte, error)
	Verify(signingString string, sig []byte, key any) error
}

type SigningMethodHMAC struct{}

func (m *SigningMethodHMAC) Sign(signingString string, key any) ([]byte, error) { return nil, nil }

func (m *SigningMethodHMAC) Verify(signingString string, sig []byte, key any) error { return nil }

var SigningMethodHS256 = &SigningMethodHMAC{}
