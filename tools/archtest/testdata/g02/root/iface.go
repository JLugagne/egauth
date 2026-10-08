package egauth

type Applier interface{ Apply(*config) }

type ErrApplier interface{ Apply(*config) error }

type Handler interface{ Handle(int) }

type applyImpl struct{}

func (applyImpl) Apply(*config) {}

func NewApplied(opts ...Applier) {}

func NewErrApplied(opts ...ErrApplier) {}

func WithApplied() Applier { return nil }

func WithErrApplied() ErrApplier { return nil }

func WithImpl() applyImpl { return applyImpl{} }

func RequireApplied() Applier { return nil }

func Chain(hs ...Handler) {}

func WithHandler() Handler { return nil }
