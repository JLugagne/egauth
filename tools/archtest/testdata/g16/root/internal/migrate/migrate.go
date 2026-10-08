package migrate

import "io/fs"

type Module struct {
	Name string
	FS   fs.FS
}
