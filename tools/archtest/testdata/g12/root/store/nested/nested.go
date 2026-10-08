package nested

import (
	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/store/good"
)

type Store interface {
	good.Store
}
