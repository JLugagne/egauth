package egauth

type Batch struct {
	Errs []error
}

type Outcome struct {
	Detail struct {
		Err error
	}
}

type Indexed struct {
	ByKey map[string]error
}

type result struct {
	Err error
}

func Do() *result { return nil }

type unreachableResult struct {
	Err error
}
