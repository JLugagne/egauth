package reg

import (
	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/good"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/internal/migrate"
)

func moduleGood() migrate.Module { return migrate.Module{Name: "good", FS: good.FS} }
