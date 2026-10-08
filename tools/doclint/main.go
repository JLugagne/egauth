// Command doclint runs the documentation guards G26 and G27 (DESIGN.md section 9.5) over the
// repository holding the nearest go.work above the working directory, or over -root.
//
// Usage, from tools/: go run ./doclint [-root dir] [-docs] [-code] [-write | -check]
//
// It exits 0 when clean, 1 when guards report findings and 2 on usage or load errors.
package main

import (
	"os"

	"github.com/JLugagne/egauth/tools/doclint/internal/lint"
)

func main() {
	os.Exit(lint.Main(os.Args[1:], os.Stdout, os.Stderr))
}
