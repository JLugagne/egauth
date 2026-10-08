package egauth

import "net/http"

type server struct{}

func (*server) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

func NewServer() *server { return nil }

func NewAnon() interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
} {
	return nil
}

type builder struct{}

func (builder) Mount() http.Handler { return nil }

func NewBuilder() builder { return builder{} }

var DefaultServer = &server{}

type unreachable struct{}

func (unreachable) Mount() http.Handler { return nil }

type valueServer struct{}

func (*valueServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

func NewValueServer() valueServer { return valueServer{} }
