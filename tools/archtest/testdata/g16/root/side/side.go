package side

import (
	"io/fs"
	"os"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/internal/migrate"
)

type alt struct {
	Name string
	FS   fs.FS
}

func Side() migrate.Module {
	m := migrate.Module{Name: "side"}
	m.FS = os.DirFS("/srv/migrations")
	return m
}

func Converted() migrate.Module { return migrate.Module(alt{Name: "c", FS: os.DirFS("y")}) }
