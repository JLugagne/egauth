package hibp

import "net/http"

func NewWithHTTPClient(c Config, hc *http.Client) *Client {
	cl := New(c)
	clone := *hc
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cl.send = clone.Do
	return cl
}
