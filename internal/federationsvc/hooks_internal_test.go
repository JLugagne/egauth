package federationsvc

import (
	"context"
	"net/http"

	"github.com/JLugagne/egauth/federation"
)

func NewWithHTTPClient(ctx context.Context, cfg Config, c *http.Client) (*Service, error) {
	return newService(ctx, cfg, httpClients{static: c, tenant: c})
}

func DiscoverWithHTTPClient(ctx context.Context, c *http.Client, p federation.Provider) (federation.Provider, error) {
	return discover(ctx, c, p)
}
