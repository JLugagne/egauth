package side

import (
	"io/fs"
	"os"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/internal/migrate"
)

func Tuple() (migrate.Module, error) {
	m := migrate.Module{Name: "tuple"}
	var err error
	m.FS, err = fs.Sub(os.DirFS("/srv"), "migrations")
	return m, err
}

func Pointer() migrate.Module {
	m := migrate.Module{Name: "ptr"}
	p := &m.FS
	*p = os.DirFS("/srv/migrations")
	return m
}

func Ranged(fss []fs.FS) migrate.Module {
	var m migrate.Module
	for _, m.FS = range fss {
	}
	return m
}
