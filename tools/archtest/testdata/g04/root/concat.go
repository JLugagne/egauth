package egauth

import "errors"

const notConf = "not " + "configured"

const prefix = "no store "

var ErrConcat = errors.New(prefix + "configured")

func Describe(name string) string { return "no " + name + " configured" }
