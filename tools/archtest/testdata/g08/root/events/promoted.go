package events

type inner struct {
	AMR        []string
	RememberMe bool
}

type Wrapped struct {
	inner
	Meta struct{ Epoch uint64 }
}

var Options struct{ Factors []string }
