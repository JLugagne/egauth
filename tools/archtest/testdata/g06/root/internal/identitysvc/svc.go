package identitysvc

import (
	"strings"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/identity"
)

func Normalize(id identity.Identifier) string { return strings.ToLower(string(id)) }
