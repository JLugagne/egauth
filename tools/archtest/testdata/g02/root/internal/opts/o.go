package opts

type Cfg struct{}

type Option func(*Cfg)

func WithX() Option { return nil }
