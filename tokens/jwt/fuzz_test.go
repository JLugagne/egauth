package jwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
)

// FuzzVerifyAccessToken fuzzes the JWT decode/verify path with arbitrary token strings. The verify
// path is alg-pinned (HS256, rejecting `none`/alg-confusion) and decodes attacker-supplied,
// untrusted token bytes; it must return an error — never panic — on any malformed or hostile input.
func FuzzVerifyAccessToken(f *testing.F) {
	svc := jwt.New(jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		Issuer:     "fuzz",
		SecretKey:  "0123456789abcdef0123456789abcdef", // 32 bytes (>= MinSecretKeyLength)
		AccessTTL:  15 * time.Minute,
		RefreshTTL: time.Hour,
	})

	f.Add("")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.")      // alg=none attempt
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.AAAA") // HS256 header, bogus sig
	f.Add("....")
	f.Add("not-base64.@@@.$$$")

	f.Fuzz(func(_ *testing.T, token string) {
		_, _ = svc.VerifyAccessToken(context.Background(), token)
	})
}
