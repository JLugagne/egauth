package reg

import (
	"os"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/internal/migrate"
)

func moduleAssign() migrate.Module {
	var m migrate.Module
	m.FS = os.DirFS("x")
	return m
}
