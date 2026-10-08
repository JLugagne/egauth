package egauth

import (
	"net/http"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g01/root/legacy"
)

func HTTPServer() *http.Server { return nil }

func HTTPClient() *http.Client { return nil }

type ServerBox struct {
	S *http.Server
}

func ExposeLegacy() legacy.Exposed { return legacy.Exposed{} }
