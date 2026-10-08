package egauth

type CauseErr struct{}

func (*CauseErr) Error() string { return "cause" }

type ValueErr struct{}

func (ValueErr) Error() string { return "value" }

type Result struct {
	Cause *CauseErr
}

type ValResult struct {
	Cause ValueErr
}

type IfaceResult struct {
	Cause interface {
		error
		Code() int
	}
}

type ListResult struct {
	Causes []*CauseErr
}

type CleanResult struct {
	Name string
}
