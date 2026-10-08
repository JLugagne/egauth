package redirect

type Target struct{ Path string }

func New() Target { return Target{Path: "/"} }
