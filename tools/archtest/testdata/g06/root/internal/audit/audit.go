package audit

import "github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/event"

func Send(s event.Sink) { s.Emit("ok") }
