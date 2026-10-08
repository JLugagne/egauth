package archtest_test

import (
	"testing"

	"github.com/JLugagne/egauth/tools/archtest"
)

func TestG10KeysBuiltOutsideTheCallFire(t *testing.T) {
	ws, cfg := fixture(t, "g10")
	assertFires(t, archtest.CheckG10(ws, cfg),
		[]string{g10 + "/app.Indirect", g10 + "/app.Prebuilt", g10 + "/app.Runtime", g10 + "/app.localKey", g10 + "/app.LocalConst"},
		[]string{g10 + "/app.Declared"})
}

func TestG10GenericConversionsFire(t *testing.T) {
	ws, cfg := fixture(t, "g10")
	assertFires(t, archtest.CheckG10(ws, cfg),
		[]string{g10 + "/app.Generic", g10 + "/app.GenericType"},
		[]string{g10 + "/app.SortedKeys", g10 + "/app.conv", g10 + "/app.box"})
}
