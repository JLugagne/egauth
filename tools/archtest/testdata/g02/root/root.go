package egauth

type RouteOption interface{ apply() }

type APIRouteOption interface{ applyAPI() }

type Sealed interface{ seal() }

type Open interface{ Do() }

type Option func(*config)

type ErrOption func(*config) error

type Mutator func(*config, int)

type config struct{}

type sealedImpl struct{}

func (sealedImpl) apply()    {}
func (sealedImpl) applyAPI() {}
func (sealedImpl) seal()     {}

func Protect(opts ...RouteOption) {}

func ProtectAPI(opts ...APIRouteOption) {}

func New(opts ...Sealed) {}

func Use(opts ...Open) {}

func RequireMFA() RouteOption { return sealedImpl{} }

func AcceptAPI() APIRouteOption { return sealedImpl{} }

func WithFoo() RouteOption { return sealedImpl{} }

func DisableBar() Sealed { return sealedImpl{} }

func RequireSealed() Sealed { return sealedImpl{} }

func WithTimeout() Option { return nil }

func AcceptErr() ErrOption { return nil }

func Build() Open { return nil }
