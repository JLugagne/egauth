package reg

import (
	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/dup"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/internal/migrate"
)

func moduleDup() migrate.Module { return migrate.Module{Name: "dup", FS: dup.FS} }

func moduleDupAgain() migrate.Module { return migrate.Module{Name: "dup2", FS: dup.FS} }
