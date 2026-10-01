package authflow

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// F-AFLOW-001 regression: the Engine HMAC secret must never survive a fmt rendering, for
// both the value and pointer forms and for every verb. fmt consults Stringer only for
// string-like verbs and only on the method set of the formatted type, so a pointer-receiver
// Stringer leaves two disclosure paths: formatting a dereferenced Engine value (fmt
// reflection then walks the unexported secret field) and non-string verbs such as %d on the
// pointer (Stringer is bypassed). The value-receiver Format method closes both paths.
func TestEngine_RedactsSecretForEveryFormatVerbAndForm(t *testing.T) {
	secret := []byte("S3cr3tFlowTokenKey0123456789abcd")
	engine, err := NewEngine(secret)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	needles := []string{
		string(secret),
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%d", secret),
		fmt.Sprintf("%x", secret),
		fmt.Sprintf("%#v", secret),
	}

	renderings := map[string]string{
		"pointer %v":  fmt.Sprintf("%v", any(engine)),
		"pointer %+v": fmt.Sprintf("%+v", any(engine)),
		"pointer %#v": fmt.Sprintf("%#v", any(engine)),
		"pointer %s":  fmt.Sprintf("%s", any(engine)),
		"pointer %x":  fmt.Sprintf("%x", any(engine)),
		"pointer %d":  fmt.Sprintf("%d", any(engine)),
		"value %v":    fmt.Sprintf("%v", any(*engine)),
		"value %+v":   fmt.Sprintf("%+v", any(*engine)),
		"value %#v":   fmt.Sprintf("%#v", any(*engine)),
		"value %s":    fmt.Sprintf("%s", any(*engine)),
		"value %x":    fmt.Sprintf("%x", any(*engine)),
		"value %d":    fmt.Sprintf("%d", any(*engine)),
	}
	for label, out := range renderings {
		for _, needle := range needles {
			if strings.Contains(out, needle) {
				t.Errorf("%s leaked the engine HMAC key (%q): %s", label, needle, out)
			}
		}
	}

	if out := fmt.Sprintf("%v", engine); !strings.Contains(out, "CookieName") {
		t.Errorf("redaction must keep the non-secret configuration visible, got %q", out)
	}
}

// TestEngine_RedactsSecretWhenLoggedAsAValue covers the structured-logging path for the value
// form, which the existing guard (pointer + slog.Any) does not exercise.
func TestEngine_RedactsSecretWhenLoggedAsAValue(t *testing.T) {
	secret := []byte("S3cr3tFlowTokenKey0123456789abcd")
	engine, err := NewEngine(secret)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("flow", "engine", *engine)
	if strings.Contains(buf.String(), string(secret)) {
		t.Errorf("slog value form leaked the engine HMAC key: %s", buf.String())
	}
}
