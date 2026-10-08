package reg

import (
	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/internal/migrate"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/misc"
)

func Modules() []migrate.Module {
	return []migrate.Module{moduleGood(), moduleDup(), moduleDupAgain(), moduleDirty(), moduleStub(), moduleNilStub(), moduleConv(), moduleEmpty(), moduleDir(), {Name: "misc", FS: misc.FS}}
}
