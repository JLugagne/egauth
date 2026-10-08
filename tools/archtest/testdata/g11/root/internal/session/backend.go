package session

type Backend interface {
	Start() error
	Resume() error
}
