package reg

import (
	"embed"
	"io/fs"
	"os"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/internal/migrate"
)

var empty embed.FS

func moduleConv() migrate.Module { return migrate.Module{Name: "conv", FS: fs.FS(nil)} }

func moduleEmpty() migrate.Module { return migrate.Module{Name: "empty", FS: empty} }

func moduleDir() migrate.Module { return migrate.Module{Name: "dir", FS: os.DirFS("x")} }
