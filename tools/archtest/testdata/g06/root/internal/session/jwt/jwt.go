package jwt

import (
	ext "github.com/JLugagne/egauth/tools/archtest/testdata/g06/ext/github.com/golang-jwt/jwt/v5"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/internal/core"
)

const claim = "amr"

func Decode(s string) { _ = ext.Parse(s); core.Renew(); core.Unseal() }
