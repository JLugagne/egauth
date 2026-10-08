package stateful

type Stateful struct{}

func (*Stateful) Start() error { return nil }

func (*Stateful) Resume() error { return nil }
