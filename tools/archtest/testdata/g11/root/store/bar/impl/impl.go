package impl

type Bar struct{}

func (*Bar) Ping() error { return nil }

func (*Bar) Other() error { return nil }
