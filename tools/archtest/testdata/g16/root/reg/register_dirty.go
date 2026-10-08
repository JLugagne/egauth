package reg

import (
	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/dirty"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/internal/migrate"
)

func moduleDirty() migrate.Module { return migrate.Module{"dirty", dirty.FS} }
