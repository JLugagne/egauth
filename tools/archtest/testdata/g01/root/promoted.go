package egauth

import "net/http"

type Server struct{ *http.ServeMux }

type Embeds struct{ http.Handler }

type Mountable interface{ http.Handler }

var Wrap = func(h http.Handler) http.Handler { return h }

var Default http.Handler

var Pattern = "/"

type Middleware func(http.HandlerFunc) http.HandlerFunc

func Chain() Middleware { return nil }

type Recorder struct{ http.ResponseWriter }

type embedsPrivate struct{ http.Handler }
