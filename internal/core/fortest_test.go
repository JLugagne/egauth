package core_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/core"
)

func TestForTestAttrsRedactsCredentialIDs(t *testing.T) {
	const marker = "CREDENTIALIDMARKER"
	f := core.ForTestAttrs{
		Factors:     []core.Factor{core.FactorPasskey},
		Credentials: []core.ForTestCredential{{Factor: core.FactorPasskey, ID: []byte(marker)}},
	}
	var outputs []string
	for _, v := range []any{f, &f} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
			outputs = append(outputs, fmt.Sprintf(verb, v))
		}
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("attrs", "attrs", v)
		outputs = append(outputs, buf.String())
	}
	hexMarker := fmt.Sprintf("%x", marker)
	for _, out := range outputs {
		if strings.Contains(out, marker) || strings.Contains(out, hexMarker) {
			t.Fatalf("ForTestAttrs leaks a credential id: %s", out)
		}
	}
}
