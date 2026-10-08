package egauth

type AliasOption = func(*config)

func NewAliased(opts ...AliasOption) {}

func WithAlias() AliasOption { return nil }

type option func(*config)

func BuildHidden(opts ...option) {}

func WithHidden() option { return nil }

func RequireHidden() option { return nil }

type sealedOpt interface{ sealOpt() }

func Configure(opts ...sealedOpt) {}

func WithSealed() sealedOpt { return nil }

func Plainly(opts ...func(*config)) {}

func WithPlain() func(*config) { return nil }

type unusedOption func(*config)
