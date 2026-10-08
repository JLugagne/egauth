package ceremony

import "github.com/JLugagne/egauth/tools/archtest/testdata/g08/root/principal"

type Record struct {
	Handle  string
	Pending []byte
	Other   principal.Sealed
}
