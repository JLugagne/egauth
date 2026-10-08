package bar

type Store interface {
	Ping() error
	Other() error
}
