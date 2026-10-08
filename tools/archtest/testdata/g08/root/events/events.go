package events

type Session struct {
	AMR        []string
	RememberMe bool
	Epoch      uint64
	Name       string
}

type Login struct {
	AuthTime           int64
	MustChangePassword bool
	Interim            bool
	ReturnTo           string
	Factors            []string
}

type clean struct{ AMR []string }

type Clean struct{ Amr []string }
