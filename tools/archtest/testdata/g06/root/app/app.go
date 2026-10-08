package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	ext "github.com/JLugagne/egauth/tools/archtest/testdata/g06/ext/github.com/golang-jwt/jwt/v5"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/ext/github.com/pquerna/otp/totp"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/event"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/identity"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/internal/core"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/internal/redirect"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/internal/session"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/store/ceremony"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/store/foo"
)

func Cookies(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "a"})
	_, _ = r.Cookie("a")
}

func Addr(r *http.Request) string { return r.RemoteAddr }

func Headers(r *http.Request) string {
	_ = r.Header.Get("sec-fetch-site")
	_ = r.Header.Get("Origin")
	return r.Header.Get("x-forwarded-for")
}

func Body(r *http.Request) {
	_ = json.NewDecoder(r.Body)
	_ = r.FormValue("a")
}

func Outbound() {
	_ = http.Client{}
	_ = &http.Transport{}
	_ = http.DefaultClient
	_, _ = http.Get("x")
}

func Ctx(ctx context.Context) {
	_ = context.WithValue(ctx, "k", 1)
	_ = ctx.Value("k")
}

func Time() { _ = time.Now() }

func Producers() {
	_ = core.NewPending()
	_ = core.NewMFADecision()
	_ = core.Pending{}.Add()
	core.Renew()
	core.Unseal()
	_ = core.ForTestAttrs()
}

func Records() {
	_ = foo.RestoreRecord()
	_ = ceremony.NewRecord()
	_ = redirect.Target{Path: "x"}
}

func Backends(b session.Backend, s event.Sink) {
	b.Start()
	b.Reissue()
	b.Resume()
	s.Emit("x")
}

func Libs(id identity.Identifier) {
	_ = ext.Parse("x")
	_ = totp.Validate("1")
	_ = strings.ToLower(string(id))
	_ = "amr"
	_ = strings.ToLower("fine")
}

func Allowed() { _ = http.StatusOK; _ = "origin-ish" }
