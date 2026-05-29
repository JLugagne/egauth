package delivery

import (
	"fmt"
	htmltemplate "html/template"
	"net/url"
	"strings"
	texttemplate "text/template"

	"github.com/JLugagne/libauth/identity"
)

// Event identifies which identity delivery message is being rendered. It selects the template
// the default Renderer executes and lets a custom Renderer branch on the flow.
type Event int

const (
	// EventPasswordReset is the password-reset link/email.
	EventPasswordReset Event = iota
	// EventEmailVerification is the address-verification link/email.
	EventEmailVerification
	// EventMagicLink is the passwordless sign-in link/email.
	EventMagicLink
	// EventEmailChange is the change-email confirmation, delivered to the NEW address.
	EventEmailChange
)

// String returns a stable, lower-case identifier for the event (used in error messages).
func (e Event) String() string {
	switch e {
	case EventPasswordReset:
		return "password_reset"
	case EventEmailVerification:
		return "email_verification"
	case EventMagicLink:
		return "magic_link"
	case EventEmailChange:
		return "email_change"
	default:
		return fmt.Sprintf("event(%d)", int(e))
	}
}

// TemplateData is the value passed to the message templates the default Renderer executes.
type TemplateData struct {
	// User is the recipient account. For EventEmailChange this is the account whose address is
	// changing; the message is delivered to NewEmail, not User.Email.
	User *identity.User
	// Link is the fully-built action URL (reset / verify / magic-link / change-confirmation),
	// produced from the configured LinkConfig (or a custom link builder) and the plaintext token.
	Link string
	// NewEmail is the address being switched to. Populated only for EventEmailChange.
	NewEmail string
}

// Renderer turns an event plus its data into a Message. Implement it to take full control of
// subjects and bodies (e.g. to localise, brand, or pull copy from your CMS); otherwise use the
// default TemplateRenderer and override individual templates with WithTemplate.
type Renderer interface {
	Render(event Event, data TemplateData) (Message, error)
}

// LinkConfig holds the base URLs the default link builder turns a plaintext token into a
// clickable action link for. The token is appended as the "token" query parameter (and, for the
// email-change confirmation, the new address as "email"), preserving any query already present
// in the base URL.
//
// A base URL is required for every flow whose handler you expose with the default templates; New
// rejects an all-empty LinkConfig unless you supply a custom Renderer (which need not use Link).
type LinkConfig struct {
	PasswordReset     string
	EmailVerification string
	MagicLink         string
	EmailChange       string
}

// empty reports whether no base URL is configured at all.
func (c LinkConfig) empty() bool {
	return c.PasswordReset == "" && c.EmailVerification == "" && c.MagicLink == "" && c.EmailChange == ""
}

// base returns the configured base URL for an event.
func (c LinkConfig) base(event Event) string {
	switch event {
	case EventPasswordReset:
		return c.PasswordReset
	case EventEmailVerification:
		return c.EmailVerification
	case EventMagicLink:
		return c.MagicLink
	case EventEmailChange:
		return c.EmailChange
	default:
		return ""
	}
}

// LinkBuilder turns a plaintext token (and, for email-change, the new address) into the action
// URL embedded in a message. Supply one with WithLinkBuilder to fully control link shape (custom
// query parameters, path-encoded tokens, deep links); the default appends ?token=...&email=...
// to the per-event base from LinkConfig.
type LinkBuilder func(event Event, token, newEmail string) string

// linkBuilderFromConfig builds the default LinkBuilder. It appends the token (and, for an
// email change, the new address) as query parameters to the configured base URL. A missing base
// yields an empty link, which the default templates surface as a clearly broken message rather
// than silently sending a tokenless link.
func linkBuilderFromConfig(cfg LinkConfig) LinkBuilder {
	return func(event Event, token, newEmail string) string {
		base := cfg.base(event)
		if base == "" {
			return ""
		}
		u, err := url.Parse(base)
		if err != nil {
			return ""
		}
		q := u.Query()
		q.Set("token", token)
		if event == EventEmailChange && newEmail != "" {
			q.Set("email", newEmail)
		}
		u.RawQuery = q.Encode()
		return u.String()
	}
}

// messageTemplate is a parsed subject+body template triple for one event.
type messageTemplate struct {
	subject *texttemplate.Template
	text    *texttemplate.Template
	html    *htmltemplate.Template // nil when the event has no HTML body
}

// TemplateRenderer is the default Renderer. It executes Go templates (text/template for the
// subject and plain-text body, html/template for the optional HTML body so user-controlled data
// is auto-escaped) against TemplateData. Built-in defaults are used for every event unless
// overridden with WithTemplate.
type TemplateRenderer struct {
	templates map[Event]messageTemplate
}

// TemplateOption configures a TemplateRenderer.
type TemplateOption func(*templateConfig)

type templateConfig struct {
	overrides map[Event]rawTemplate
}

type rawTemplate struct {
	subject string
	text    string
	html    string // optional
}

// WithTemplate overrides the templates for one event. subject and text are parsed as
// text/template, html (when non-empty) as html/template. The templates receive TemplateData;
// {{.Link}}, {{.User.Email}} and (for email-change) {{.NewEmail}} are the useful fields. Parse
// errors are reported by NewTemplateRenderer.
func WithTemplate(event Event, subject, text, html string) TemplateOption {
	return func(c *templateConfig) {
		c.overrides[event] = rawTemplate{subject: subject, text: text, html: html}
	}
}

// NewTemplateRenderer builds the default Renderer, applying any WithTemplate overrides. It
// returns an error if a template fails to parse (fail-fast at construction rather than at send
// time).
func NewTemplateRenderer(opts ...TemplateOption) (*TemplateRenderer, error) {
	cfg := templateConfig{overrides: map[Event]rawTemplate{}}
	for _, opt := range opts {
		opt(&cfg)
	}

	raw := defaultTemplates()
	for event, override := range cfg.overrides {
		raw[event] = override
	}

	parsed := make(map[Event]messageTemplate, len(raw))
	for event, rt := range raw {
		mt, err := parseTemplate(event, rt)
		if err != nil {
			return nil, err
		}
		parsed[event] = mt
	}
	return &TemplateRenderer{templates: parsed}, nil
}

func parseTemplate(event Event, rt rawTemplate) (messageTemplate, error) {
	name := event.String()
	subject, err := texttemplate.New(name + ":subject").Parse(rt.subject)
	if err != nil {
		return messageTemplate{}, fmt.Errorf("delivery: parsing %s subject template: %w", name, err)
	}
	text, err := texttemplate.New(name + ":text").Parse(rt.text)
	if err != nil {
		return messageTemplate{}, fmt.Errorf("delivery: parsing %s text template: %w", name, err)
	}
	mt := messageTemplate{subject: subject, text: text}
	if rt.html != "" {
		html, err := htmltemplate.New(name + ":html").Parse(rt.html)
		if err != nil {
			return messageTemplate{}, fmt.Errorf("delivery: parsing %s html template: %w", name, err)
		}
		mt.html = html
	}
	return mt, nil
}

// Render executes the template for event against data.
func (r *TemplateRenderer) Render(event Event, data TemplateData) (Message, error) {
	mt, ok := r.templates[event]
	if !ok {
		return Message{}, fmt.Errorf("delivery: no template for event %s", event)
	}

	subject, err := execText(mt.subject, data)
	if err != nil {
		return Message{}, err
	}
	text, err := execText(mt.text, data)
	if err != nil {
		return Message{}, err
	}
	msg := Message{
		// A subject is a single header line: collapse any stray newlines so a multi-line
		// template (or injected data) cannot smuggle extra headers into the email.
		Subject: strings.Join(strings.Fields(subject), " "),
		Text:    text,
	}
	if mt.html != nil {
		var sb strings.Builder
		if err := mt.html.Execute(&sb, data); err != nil {
			return Message{}, fmt.Errorf("delivery: rendering %s html: %w", event, err)
		}
		msg.HTML = sb.String()
	}
	return msg, nil
}

func execText(t *texttemplate.Template, data TemplateData) (string, error) {
	var sb strings.Builder
	if err := t.Execute(&sb, data); err != nil {
		return "", fmt.Errorf("delivery: rendering %s: %w", t.Name(), err)
	}
	return sb.String(), nil
}

// defaultTemplates returns the built-in, brandable plain-text copy for each identity event. They
// are deliberately plain and provider-neutral; override them with WithTemplate to add branding,
// HTML, or localisation.
func defaultTemplates() map[Event]rawTemplate {
	return map[Event]rawTemplate{
		EventPasswordReset: {
			subject: "Reset your password",
			text: "Hello,\n\n" +
				"We received a request to reset the password for your account. " +
				"Open the link below to choose a new password:\n\n" +
				"{{.Link}}\n\n" +
				"If you did not request this, you can safely ignore this email — " +
				"your password will not change.\n",
		},
		EventEmailVerification: {
			subject: "Verify your email address",
			text: "Hello,\n\n" +
				"Please confirm this email address by opening the link below:\n\n" +
				"{{.Link}}\n\n" +
				"If you did not create an account, you can ignore this email.\n",
		},
		EventMagicLink: {
			subject: "Your sign-in link",
			text: "Hello,\n\n" +
				"Use the link below to sign in. It can be used once and expires shortly:\n\n" +
				"{{.Link}}\n\n" +
				"If you did not try to sign in, you can ignore this email.\n",
		},
		EventEmailChange: {
			subject: "Confirm your new email address",
			text: "Hello,\n\n" +
				"A request was made to change the email address on your account to " +
				"{{.NewEmail}}. To confirm the change, open the link below:\n\n" +
				"{{.Link}}\n\n" +
				"If you did not request this, you can ignore this email and your address " +
				"will stay the same.\n",
		},
	}
}
