package event

type Type string

type AttrKey string

const (
	TypeLogin Type = "login"

	KeyMethod AttrKey = "method"
	KeyIP     AttrKey = "ip"
	KeyFresh  AttrKey = "fresh"
)

func (k AttrKey) Sensitivity() int {
	switch k {
	case KeyMethod:
		return 1
	case KeyIP:
		return 2
	}
	return 3
}
