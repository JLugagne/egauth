package egauth_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth"
)

func TestDelivererHasOneMethodPerKind(t *testing.T) {
	if n := reflect.TypeFor[egauth.EmailDeliverer]().NumMethod(); n != 9 {
		t.Fatalf("email deliverer: want 9 methods, got %d", n)
	}
	if n := reflect.TypeFor[egauth.SMSDeliverer]().NumMethod(); n != 4 {
		t.Fatalf("sms deliverer: want 4 methods, got %d", n)
	}
	if egauth.SecurityCredentialRotated != 1 || egauth.SecurityFactorsChanged != 2 || egauth.SecurityIdentifierChanged != 3 {
		t.Fatal("security event values must not move")
	}
	if egauth.SecurityEvent(0).String() != "invalid" || egauth.SecurityEvent(4).String() != "invalid" {
		t.Fatal("undeclared security events must be invalid")
	}
}

func TestDeliveryMessagesRedactOneTimeSecrets(t *testing.T) {
	const (
		link   = "https://app.example.com/magic?token=LINKSECRET0123456789"
		code   = "424242"
		revert = "https://app.example.com/security/revert?token=REVERTSECRET0123456789"
		to     = "owner@example.com"
	)
	id := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	cases := []struct {
		name   string
		msg    any
		secret string
	}{
		{"link", egauth.LinkMessage{DeliveryID: id, To: to, Link: link}, link},
		{"code", egauth.CodeMessage{DeliveryID: id, To: to, Code: code}, code},
		{"security notice", egauth.SecurityNoticeMessage{
			DeliveryID: id, To: to, Event: egauth.SecurityFactorsChanged, Summary: "factors changed", RevertLink: revert,
		}, revert},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ptr := reflect.New(reflect.TypeOf(c.msg))
			ptr.Elem().Set(reflect.ValueOf(c.msg))
			var outputs []string
			for _, v := range []any{c.msg, ptr.Interface()} {
				for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d", "%t", "%10.3v"} {
					outputs = append(outputs, fmt.Sprintf(verb, v))
				}
				var buf bytes.Buffer
				slog.New(slog.NewTextHandler(&buf, nil)).Info("deliver", "msg", v)
				outputs = append(outputs, buf.String())
				buf.Reset()
				slog.New(slog.NewJSONHandler(&buf, nil)).Info("deliver", "msg", v)
				outputs = append(outputs, buf.String())
			}
			for _, out := range outputs {
				if strings.Contains(out, c.secret) {
					t.Fatalf("formatted message leaks its one-time secret: %s", out)
				}
				if !strings.Contains(out, id.String()) {
					t.Fatalf("formatted message lost its delivery id: %s", out)
				}
			}
		})
	}
}

func TestSecurityNoticeWithoutClientRendersNoBogusIP(t *testing.T) {
	m := egauth.SecurityNoticeMessage{Event: egauth.SecurityFactorsChanged}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("deliver", "msg", m)
	for _, out := range []string{m.String(), buf.String()} {
		if strings.Contains(out, "invalid IP") {
			t.Fatalf("a notice with no client renders a bogus address: %s", out)
		}
	}
}
