package signing

// NewTestMinter grants a Minter to this package's external tests, which cannot declare an owner in
// internal/session/jwt.
func NewTestMinter() *Minter { return &Minter{granted: true} }
