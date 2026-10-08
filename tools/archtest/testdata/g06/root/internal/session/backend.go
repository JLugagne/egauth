package session

type Backend interface {
	Start()
	Reissue()
	Resume()
}
