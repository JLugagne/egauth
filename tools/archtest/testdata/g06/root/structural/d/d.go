package d

import (
	"context"
	"net/http"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/internal/session"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/kek"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/structural/a"
)

type valuer interface{ Value(key any) any }

type former interface{ FormValue(key string) string }

type starter interface{ Start() }

type ctxWrap struct{ context.Context }

type kekWrap struct{ kek.KEK }

type both interface {
	context.Context
	Extra()
}

type beWrap struct{ session.Backend }

type reqWrap struct{ *http.Request }

type ownSealer struct{}

func (ownSealer) Seal(p []byte) ([]byte, error) { return p, nil }

func EmbedCtx(ctx context.Context) {
	var v valuer = ctxWrap{ctx}
	_ = v
}

func EmbedKEK(k kek.KEK) { a.Do(kekWrap{k}) }

func IfaceEmbed(b both) {
	var v valuer = b
	_ = v
}

func EmbedBackend(b session.Backend) {
	var s starter = &beWrap{b}
	_ = s
}

func EmbedReq(r *http.Request) {
	var f former = reqWrap{r}
	_ = f
}

func KeepCtx(ctx context.Context) context.Context { return ctxWrap{ctx} }

func OwnSeal() { a.Do(ownSealer{}) }
