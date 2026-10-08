package egauth

import "fmt"

func sniffInTest(v any) bool {
	_, ok := v.(fmt.Stringer)
	return ok
}
