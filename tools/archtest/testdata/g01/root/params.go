package egauth

import "net/http"

func Fill(dst *http.Handler) {}

func Expose(cb func(h http.Handler)) {}

func FillAll(dst []http.Handler) {}

type Sink interface{ Put(h http.Handler) }

func Register(s interface{ Put(h http.Handler) }) {}

type Hook func(h http.Handler)

func SetHook(h Hook) {}

func NonAdjacent(w http.ResponseWriter, id string, r *http.Request) {}

func Use(h http.Handler) {}

func UseFunc(fn http.HandlerFunc) {}

func Take(name string, fn func() string) {}

func Write(w http.ResponseWriter, body []byte) {}

func RegisterSink(s Sink) {}
