package jwt

import (
	"reflect"

	"github.com/JLugagne/egauth/signing"
)

var (
	ClaimSetType = reflect.TypeFor[claimSet]()
	HeaderType   = reflect.TypeFor[header]()
)

func SignForTest(s signing.Signer, headerJSON, payloadJSON []byte) (string, error) {
	m, err := signing.NewMinter(signingOwner{})
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(headerJSON) + "." + b64.EncodeToString(payloadJSON)
	sig, err := m.Sign(s, input)
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}
