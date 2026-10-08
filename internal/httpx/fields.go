package httpx

import (
	"slices"

	"github.com/JLugagne/egauth/internal/csrf"
)

// HeaderTransport is csrf.HeaderTransport, which mirrors routes.HeaderTransport (routes imports
// httpx, so neither can import routes); a guard test in internal/routes keeps them equal.
const HeaderTransport = csrf.HeaderTransport

const (
	fieldIdentifier   = "identifier"
	fieldCaptchaToken = "captcha_token"
)

var fieldNames = []string{
	"identifier",
	"password",
	"new_password",
	"remember",
	"return_to",
	"code",
	"factor",
	"email",
	"phone",
	"token",
	"flow",
	"handle",
	"bind",
	"credential_id",
	"nickname",
	"confirm",
	"captcha_token",
	"resource",
}

// FieldNames returns a copy of the closed request field set the parser keeps. It mirrors
// routes.Fields; a guard test in internal/routes keeps the two equal.
func FieldNames() []string {
	return slices.Clone(fieldNames)
}

func isField(name string) bool {
	return slices.Contains(fieldNames, name)
}
