package app

import (
	"encoding/json"
	"io"
	"net/http"

	ext "github.com/JLugagne/egauth/tools/archtest/testdata/g06/ext/github.com/golang-jwt/jwt/v5"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/internal/core"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/kek"
)

type sealer interface {
	Seal(p []byte) ([]byte, error)
}

type wrapper struct{ kek.KEK }

func JWTSign() { _, _ = ext.SigningMethodHS256.Sign("x", nil) }

func JWTVerify(m *ext.SigningMethodHMAC) { _ = m.Verify("x", nil, nil) }

func ConcreteSeal(l *kek.Local) { _, _ = l.Seal(nil) }

func Structural(k kek.KEK) {
	var s sealer = k
	_, _ = s.Seal(nil)
}

func Embedded(w wrapper) { _, _ = w.Open(nil) }

func AliasedBody(r *http.Request) {
	body := r.Body
	_ = json.NewDecoder(body)
}

func LimitedBody(r *http.Request) { _ = json.NewDecoder(io.LimitReader(r.Body, 10)) }

func ZeroClient() {
	_ = new(http.Client)
	var t http.Transport
	_ = t
}

type holder struct{ c http.Client }

func States() {
	_ = core.NewAccountState()
	_ = core.NewVerified()
}
