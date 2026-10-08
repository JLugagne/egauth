package identitysvc

import "github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/internal/core"

func State() int { return core.NewAccountState() }
