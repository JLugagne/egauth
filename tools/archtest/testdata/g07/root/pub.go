package egauth

import (
	"github.com/JLugagne/egauth/tools/archtest/testdata/g07/root/event"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g07/root/internal/x"
)

type Nested struct{ Opts struct{ AllowHTTP bool } }

var Options struct{ SkipCSRF bool }

type options struct{ DisableRateLimit bool }

func Defaults() options { return options{} }

type hidden struct{ SkipHidden bool }

type Holder struct {
	Insecure InsecureOptOuts
	SkipAll  InsecureOptOuts
}

const SkipEvent event.Type = "skip"

func Exposed() x.Knobs { return x.Knobs{} }
