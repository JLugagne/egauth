package delivery

import (
	"testing"

	"github.com/JLugagne/libauth/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testUser(email string) *identity.User {
	return &identity.User{Email: email}
}

func TestTemplateRenderer_Defaults(t *testing.T) {
	r, err := NewTemplateRenderer()
	require.NoError(t, err)

	cases := []struct {
		event Event
		data  TemplateData
	}{
		{EventPasswordReset, TemplateData{User: testUser("a@x.com"), Link: "https://app/reset?token=abc"}},
		{EventEmailVerification, TemplateData{User: testUser("a@x.com"), Link: "https://app/verify?token=abc"}},
		{EventMagicLink, TemplateData{User: testUser("a@x.com"), Link: "https://app/signin?token=abc"}},
		{EventEmailChange, TemplateData{User: testUser("a@x.com"), Link: "https://app/confirm?token=abc", NewEmail: "new@x.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.event.String(), func(t *testing.T) {
			msg, err := r.Render(tc.event, tc.data)
			require.NoError(t, err)
			assert.NotEmpty(t, msg.Subject)
			assert.Contains(t, msg.Text, tc.data.Link, "body must embed the action link")
			assert.Empty(t, msg.HTML, "default templates are text-only")
			if tc.event == EventEmailChange {
				assert.Contains(t, msg.Text, tc.data.NewEmail, "email-change body must name the new address")
			}
		})
	}
}

func TestTemplateRenderer_SubjectCollapsesNewlines(t *testing.T) {
	// A multi-line subject template (or injected newline) must not be able to smuggle extra
	// headers into the email; Render collapses the subject to a single line.
	r, err := NewTemplateRenderer(WithTemplate(EventMagicLink, "Sign in\r\nBcc: attacker@evil.com", "body {{.Link}}", ""))
	require.NoError(t, err)

	msg, err := r.Render(EventMagicLink, TemplateData{User: testUser("a@x.com"), Link: "https://app/x"})
	require.NoError(t, err)
	assert.Equal(t, "Sign in Bcc: attacker@evil.com", msg.Subject)
	assert.NotContains(t, msg.Subject, "\n")
	assert.NotContains(t, msg.Subject, "\r")
}

func TestTemplateRenderer_Override(t *testing.T) {
	r, err := NewTemplateRenderer(WithTemplate(
		EventPasswordReset,
		"Custom subject for {{.User.Email}}",
		"plain {{.Link}}",
		"<p>html <a href=\"{{.Link}}\">reset</a></p>",
	))
	require.NoError(t, err)

	msg, err := r.Render(EventPasswordReset, TemplateData{User: testUser("user@x.com"), Link: "https://app/r?token=t"})
	require.NoError(t, err)
	assert.Equal(t, "Custom subject for user@x.com", msg.Subject)
	assert.Equal(t, "plain https://app/r?token=t", msg.Text)
	assert.Contains(t, msg.HTML, `href="https://app/r?token=t"`)
}

func TestTemplateRenderer_HTMLAutoEscapes(t *testing.T) {
	// html/template must auto-escape user-controlled data interpolated into the HTML body.
	r, err := NewTemplateRenderer(WithTemplate(
		EventEmailVerification,
		"Verify",
		"text {{.Link}}",
		"<p>Hello {{.User.Email}}</p>",
	))
	require.NoError(t, err)

	msg, err := r.Render(EventEmailVerification, TemplateData{User: testUser("a<script>@x.com"), Link: "https://app/v"})
	require.NoError(t, err)
	assert.NotContains(t, msg.HTML, "<script>", "raw markup must be escaped")
	assert.Contains(t, msg.HTML, "&lt;script&gt;")
}

func TestTemplateRenderer_ParseErrorFailsFast(t *testing.T) {
	_, err := NewTemplateRenderer(WithTemplate(EventMagicLink, "ok", "{{.Link", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "magic_link")
}

func TestTemplateRenderer_UnknownEvent(t *testing.T) {
	r, err := NewTemplateRenderer()
	require.NoError(t, err)
	_, err = r.Render(Event(99), TemplateData{User: testUser("a@x.com")})
	require.Error(t, err)
}

func TestLinkBuilderFromConfig(t *testing.T) {
	build := linkBuilderFromConfig(LinkConfig{
		PasswordReset: "https://app.example.com/reset",
		EmailChange:   "https://app.example.com/confirm?ref=email", // pre-existing query preserved
		MagicLink:     "", // unconfigured
	})

	t.Run("appends token", func(t *testing.T) {
		got := build(EventPasswordReset, "tok123", "")
		assert.Equal(t, "https://app.example.com/reset?token=tok123", got)
	})
	t.Run("email-change adds email and preserves query", func(t *testing.T) {
		got := build(EventEmailChange, "tok123", "new@x.com")
		assert.Contains(t, got, "ref=email")
		assert.Contains(t, got, "token=tok123")
		assert.Contains(t, got, "email=new%40x.com")
	})
	t.Run("unconfigured base yields empty", func(t *testing.T) {
		assert.Equal(t, "", build(EventMagicLink, "tok", ""))
	})
}
