package egauth

import "net/http"

type Routes struct{}

func (*Routes) Handler() http.Handler { return nil }

type APIRoutes struct{}

func (*APIRoutes) Handler() http.Handler { return nil }

type PrincipalHandler func(w http.ResponseWriter, r *http.Request)

func (PrincipalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

func BadHandler() http.Handler { return nil }

func BadHandlerFunc() http.HandlerFunc { return nil }

func BadMiddleware() func(http.Handler) http.Handler { return nil }

func Serve(w http.ResponseWriter, r *http.Request) {}

func ServeAfter(prefix string, w http.ResponseWriter, r *http.Request) {}

type BadFunc func(w http.ResponseWriter, r *http.Request)

type Surface interface {
	ServeX(w http.ResponseWriter, r *http.Request)
}

type Other struct{}

func (Other) Mount() http.Handler { return nil }

func Plain() string { return "" }

func Reverse(r *http.Request, w http.ResponseWriter) {}
