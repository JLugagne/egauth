// Package alpha is a fixture.
package alpha

// Server is a fixture type.
type Server struct{ Addr string }

// Start is a fixture method.
func (s *Server) Start() {}

// New builds a Server. You must also call Start on every call.
func New() *Server { return &Server{} }

// Safe documents the contract. doclint:enforced-by alpha.TestEnforced
func Safe() {}

func hidden() {}

// Mode is a fixture constant.
const Mode = 1
