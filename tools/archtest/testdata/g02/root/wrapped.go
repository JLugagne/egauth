package egauth

type Opt struct {
	Fn func(*config)
}

func Setup(opts ...Opt) {}

func WithWrapped() Opt { return Opt{} }

func RequireWrapped() Opt { return Opt{} }

type hiddenOpt struct {
	fn func(*config) error
}

func SetupHidden(opts ...*hiddenOpt) {}

func WithHiddenWrapped() *hiddenOpt { return nil }

type Plain struct {
	Name string
}

func Many(ps ...Plain) {}

func NewPlain() Plain { return Plain{} }
