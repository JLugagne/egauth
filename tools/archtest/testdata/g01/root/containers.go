package egauth

import "net/http"

func RawHandler() func(http.ResponseWriter, *http.Request) { return nil }

func RawMiddleware() func(func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return nil
}

func ErrHandler() func(http.ResponseWriter, *http.Request) error { return nil }

func HandlerSlice() []http.Handler { return nil }

func HandlerMap() map[string]http.Handler { return nil }

func AnonIface() interface{ Handler() http.Handler } { return nil }

func AnonStruct() struct{ H http.Handler } { return struct{ H http.Handler }{} }

type Mux struct {
	H    http.Handler
	Name string
}

func NewMux() *Mux { return nil }

type handlers []http.Handler

func NewHandlers() handlers { return nil }

var RawVar func(http.ResponseWriter, *http.Request)

var HandlerList []http.Handler

func Plainer() func(string) string { return nil }

type Opts struct {
	Name string
	Fn   func(int) int
	Wrap func(http.Handler)
}

func NewOpts() Opts { return Opts{} }
