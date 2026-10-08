package main

import (
	"log/slog"
	"net/http"
)

func BuildServer(logger *slog.Logger, publicOrigin string) (http.Handler, func() error, error) {
	return nil, nil, nil
}

func ServeIt(w http.ResponseWriter, r *http.Request) {}

type Exposed struct{ H http.Handler }

func main() {}
