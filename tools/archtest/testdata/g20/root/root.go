package egauth

import (
	"errors"
	"net/http"
)

var (
	_ = errors.As
	_ http.Flusher
)

type Thing struct {
	Field int
}

func (Thing) Method() {}

func Func() {}
