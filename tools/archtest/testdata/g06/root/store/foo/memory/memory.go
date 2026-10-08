package memory

import "github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/store/foo"

func New() int { return foo.RestoreRecord() }
