package legacy

import "net/http"

type Exposed struct {
	H http.Handler
}

type Kept struct {
	H http.Handler
}
