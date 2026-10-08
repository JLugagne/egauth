package egauth

type ClaimRequirement struct{ role string }

func (ClaimRequirement) apply()    {}
func (ClaimRequirement) applyAPI() {}

type SessionRequirement struct{ fresh int }

func (*SessionRequirement) apply() {}

type Unrelated struct{}

func WithRole(role string) ClaimRequirement { return ClaimRequirement{role: role} }

func Fresh() *SessionRequirement { return nil }

func RequireAnyRole(role string, more ...string) ClaimRequirement { return ClaimRequirement{} }

func AcceptMustChange() SessionRequirement { return SessionRequirement{} }

func NewUnrelated() Unrelated { return Unrelated{} }
