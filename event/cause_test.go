package event_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/event"
)

const causePII = "550 mailbox jane@example.com unavailable"

func TestCauseNeverRendersItsText(t *testing.T) {
	c := event.CauseOf(errors.New(causePII))
	renders := map[string]string{
		"%v":          fmt.Sprintf("%v", c),
		"%+v":         fmt.Sprintf("%+v", c),
		"%#v":         fmt.Sprintf("%#v", c),
		"%s":          fmt.Sprintf("%s", c),
		"%q":          fmt.Sprintf("%q", c),
		"%v of Event": fmt.Sprintf("%v", event.Event{Err: c}),
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "cause", c, "event", event.Event{Err: c})
	renders["slog text"] = buf.String()
	buf.Reset()
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", slog.Any("cause", c))
	renders["slog json"] = buf.String()
	for verb, got := range renders {
		if strings.Contains(got, "jane@example.com") || strings.Contains(got, "mailbox") {
			t.Errorf("%s leaks the cause text: %s", verb, got)
		}
	}
	if !strings.Contains(renders["%v"], "*errors.errorString") {
		t.Errorf("%%v = %q, want the dynamic type", renders["%v"])
	}
	if got := (event.Cause{}).String(); got != "<nil>" {
		t.Errorf("zero Cause renders %q", got)
	}
	if c.Text() != causePII {
		t.Error("Text must still return the text for a sink cleared for PII")
	}
}
