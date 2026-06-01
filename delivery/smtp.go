package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/JLugagne/egauth/identity"
)

// TLSMode selects how the SMTP connection is secured.
type TLSMode int

const (
	// TLSStartTLS dials plaintext then upgrades with STARTTLS. This is the default and the
	// common submission posture (port 587). If the server does not advertise STARTTLS the send
	// fails closed rather than transmitting credentials or PII in the clear.
	TLSStartTLS TLSMode = iota
	// TLSImplicit dials directly over TLS (SMTPS, port 465).
	TLSImplicit
	// TLSNone uses an unencrypted connection. It is intended only for a local relay on a trusted
	// network or a test server; never use it across an untrusted network.
	TLSNone
)

const (
	defaultSMTPPort = 587
	defaultTimeout  = 30 * time.Second
)

// ErrSTARTTLSUnsupported is returned when TLSStartTLS is configured but the server does not
// advertise the STARTTLS extension. The mailer refuses to continue rather than send credentials
// or personal data over an unencrypted link.
var ErrSTARTTLSUnsupported = errors.New("delivery: server does not support STARTTLS")

// SMTPConfig is the connection configuration for SMTPMailer.
type SMTPConfig struct {
	// Host is the SMTP server hostname (required).
	Host string
	// Port is the SMTP server port (default 587).
	Port int
	// Username and Password authenticate to the server via SMTP AUTH PLAIN. Leave Username empty
	// to disable authentication (e.g. an open local relay or a test server).
	Username string
	Password string
	// From is the sender address placed in the envelope and the From header (required), e.g.
	// "no-reply@example.com".
	From string
	// FromName is the optional display name shown alongside From, e.g. "Example Security".
	FromName string
	// TLS selects the transport security mode (default TLSStartTLS).
	TLS TLSMode
}

// SMTPMailer is a reference identity.Mailer backed by the standard library net/smtp. It renders
// each identity flow's message with a Renderer (the default TemplateRenderer unless overridden),
// builds the action link from a LinkBuilder, and delivers it over SMTP.
//
// It is a reference implementation: it covers AUTH PLAIN over STARTTLS/implicit TLS and
// multipart/alternative bodies, which suffices for a typical submission relay. Production
// deployments with high volume, bounce handling, or provider-specific APIs (SES, SendGrid,
// Postmark, ...) should implement identity.Mailer directly against their provider — that is
// exactly what the interface seam is for.
//
// SMTPMailer also satisfies Sender, so it can deliver OTP codes by email (see OTPDelivery).
type SMTPMailer struct {
	host      string
	port      int
	from      mail.Address
	auth      smtp.Auth
	tlsMode   TLSMode
	tlsConfig *tls.Config
	renderer  Renderer
	link      LinkBuilder
	timeout   time.Duration
	now       func() time.Time
	dialFunc  func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Option configures an SMTPMailer.
type Option func(*SMTPMailer)

// WithRenderer replaces the default TemplateRenderer. A custom Renderer is free to ignore
// TemplateData.Link, so supplying one also lifts New's requirement that links be configured.
func WithRenderer(r Renderer) Option {
	return func(m *SMTPMailer) {
		if r != nil {
			m.renderer = r
		}
	}
}

// WithLinks sets the per-flow base URLs the default link builder appends the token to. Required
// for the default templates unless a custom Renderer is supplied. An all-empty LinkConfig is
// treated as if no links were supplied, so NewSMTPMailer rejects it for the default templates
// (rather than silently shipping emails with empty links).
func WithLinks(cfg LinkConfig) Option {
	return func(m *SMTPMailer) {
		if !cfg.empty() {
			m.link = linkBuilderFromConfig(cfg)
		}
	}
}

// WithLinkBuilder supplies a custom LinkBuilder, taking full control of action-URL shape.
func WithLinkBuilder(b LinkBuilder) Option {
	return func(m *SMTPMailer) {
		if b != nil {
			m.link = b
		}
	}
}

// WithTLSConfig overrides the *tls.Config used for STARTTLS / implicit TLS. By default the
// server hostname is used as ServerName and TLS 1.2 is the floor.
func WithTLSConfig(c *tls.Config) Option {
	return func(m *SMTPMailer) {
		if c != nil {
			m.tlsConfig = c
		}
	}
}

// WithTimeout bounds a single send (dial + SMTP conversation). Default 30s. A non-positive value
// disables the mailer-level timeout (the context deadline, if any, still applies).
func WithTimeout(d time.Duration) Option {
	return func(m *SMTPMailer) { m.timeout = d }
}

// NewSMTPMailer builds an SMTPMailer. It validates the configuration and fails fast: Host and a
// parseable From are required, and the default templates require links (WithLinks /
// WithLinkBuilder) unless a custom Renderer is supplied.
func NewSMTPMailer(cfg SMTPConfig, opts ...Option) (*SMTPMailer, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, errors.New("delivery: SMTP host is required")
	}
	if strings.TrimSpace(cfg.From) == "" {
		return nil, errors.New("delivery: SMTP From address is required")
	}
	fromAddr, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("delivery: invalid From address %q: %w", cfg.From, err)
	}
	if cfg.FromName != "" {
		fromAddr.Name = cfg.FromName
	}
	port := cfg.Port
	if port == 0 {
		port = defaultSMTPPort
	}

	defaultRenderer, err := NewTemplateRenderer()
	if err != nil {
		return nil, err
	}

	m := &SMTPMailer{
		host:      cfg.Host,
		port:      port,
		from:      *fromAddr,
		tlsMode:   cfg.TLS,
		tlsConfig: &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12},
		renderer:  defaultRenderer,
		timeout:   defaultTimeout,
		now:       time.Now,
	}
	if cfg.Username != "" {
		m.auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	// Track whether the caller supplied their own renderer so we can require links only for the
	// default templates (which reference {{.Link}}).
	customRenderer := false
	for _, opt := range opts {
		before := m.renderer
		opt(m)
		if m.renderer != before {
			customRenderer = true
		}
	}

	if m.link == nil && !customRenderer {
		return nil, errors.New("delivery: the default templates require WithLinks (or supply a custom WithRenderer)")
	}
	if m.link == nil {
		// Custom renderer with no links configured: links resolve to empty strings.
		m.link = func(Event, string, string) string { return "" }
	}
	return m, nil
}

// SendPasswordReset implements identity.Mailer.
func (m *SMTPMailer) SendPasswordReset(ctx context.Context, user *identity.User, token string) error {
	return m.deliver(ctx, EventPasswordReset, user, user.Email, "", token)
}

// SendEmailVerification implements identity.Mailer.
func (m *SMTPMailer) SendEmailVerification(ctx context.Context, user *identity.User, token string) error {
	return m.deliver(ctx, EventEmailVerification, user, user.Email, "", token)
}

// SendMagicLink implements identity.Mailer.
func (m *SMTPMailer) SendMagicLink(ctx context.Context, user *identity.User, token string) error {
	return m.deliver(ctx, EventMagicLink, user, user.Email, "", token)
}

// SendEmailChange implements identity.Mailer. The confirmation is delivered to newEmail (the
// address being switched to), since opening it proves control of the new address.
func (m *SMTPMailer) SendEmailChange(ctx context.Context, user *identity.User, newEmail, token string) error {
	return m.deliver(ctx, EventEmailChange, user, newEmail, newEmail, token)
}

// deliver renders the event and sends the resulting message to recipient.
func (m *SMTPMailer) deliver(ctx context.Context, event Event, user *identity.User, recipient, newEmail, token string) error {
	if recipient == "" {
		return fmt.Errorf("delivery: no recipient address for %s", event)
	}
	msg, err := m.renderer.Render(event, TemplateData{
		User:     user,
		Link:     m.link(event, token, newEmail),
		NewEmail: newEmail,
	})
	if err != nil {
		return err
	}
	return m.Send(ctx, recipient, msg)
}

// Send delivers a rendered Message to a single email recipient. It satisfies the Sender
// interface, so an SMTPMailer can also carry OTP codes (see OTPDelivery).
func (m *SMTPMailer) Send(ctx context.Context, recipient string, msg Message) error {
	to, err := mail.ParseAddress(recipient)
	if err != nil {
		return fmt.Errorf("delivery: invalid recipient %q: %w", recipient, err)
	}
	raw, err := m.compose(*to, msg)
	if err != nil {
		return err
	}
	return m.send(ctx, to.Address, raw)
}

// compose builds the RFC 5322 message bytes (CRLF line endings, RFC 2047-encoded subject,
// quoted-printable bodies; multipart/alternative when an HTML body is present).
func (m *SMTPMailer) compose(to mail.Address, msg Message) ([]byte, error) {
	var b strings.Builder
	writeHeader := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }

	writeHeader("From", m.from.String())
	writeHeader("To", to.String())
	writeHeader("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	writeHeader("Date", m.now().Format(time.RFC1123Z))
	writeHeader("MIME-Version", "1.0")

	if !msg.hasHTML() {
		writeHeader("Content-Type", "text/plain; charset=utf-8")
		writeHeader("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		if err := writeQuotedPrintable(&b, msg.Text); err != nil {
			return nil, err
		}
		return []byte(b.String()), nil
	}

	mw := multipart.NewWriter(&b)
	writeHeader("Content-Type", `multipart/alternative; boundary="`+mw.Boundary()+`"`)
	b.WriteString("\r\n")
	if err := writePart(mw, "text/plain; charset=utf-8", msg.Text); err != nil {
		return nil, err
	}
	if err := writePart(mw, "text/html; charset=utf-8", msg.HTML); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("delivery: closing multipart body: %w", err)
	}
	return []byte(b.String()), nil
}

func writePart(mw *multipart.Writer, contentType, body string) error {
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", contentType)
	h.Set("Content-Transfer-Encoding", "quoted-printable")
	w, err := mw.CreatePart(h)
	if err != nil {
		return fmt.Errorf("delivery: creating message part: %w", err)
	}
	qp := quotedprintable.NewWriter(w)
	if _, err := qp.Write([]byte(body)); err != nil {
		return fmt.Errorf("delivery: writing message part: %w", err)
	}
	return qp.Close()
}

func writeQuotedPrintable(b *strings.Builder, body string) error {
	qp := quotedprintable.NewWriter(b)
	if _, err := qp.Write([]byte(body)); err != nil {
		return fmt.Errorf("delivery: encoding body: %w", err)
	}
	return qp.Close()
}

// send opens the SMTP connection (honouring the context for cancellation and the configured
// timeout), performs the conversation, and delivers raw to a single recipient.
func (m *SMTPMailer) send(ctx context.Context, to string, raw []byte) error {
	if m.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.timeout)
		defer cancel()
	}

	addr := net.JoinHostPort(m.host, strconv.Itoa(m.port))
	conn, err := m.dialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("delivery: dialing %s: %w", addr, err)
	}
	// Honour context cancellation for the whole SMTP conversation: a deadline bounds blocking
	// reads/writes, and AfterFunc tears the connection down if the context is cancelled.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if m.tlsMode == TLSImplicit {
		conn = tls.Client(conn, m.tlsConfig)
	}

	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("delivery: SMTP handshake: %w", err)
	}
	defer func() { _ = c.Close() }()

	if m.tlsMode == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return ErrSTARTTLSUnsupported
		}
		if err := c.StartTLS(m.tlsConfig); err != nil {
			return fmt.Errorf("delivery: STARTTLS: %w", err)
		}
	}
	if m.auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(m.auth); err != nil {
				return fmt.Errorf("delivery: SMTP auth: %w", err)
			}
		}
	}
	if err := c.Mail(m.from.Address); err != nil {
		return fmt.Errorf("delivery: MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("delivery: RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("delivery: DATA: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return fmt.Errorf("delivery: writing message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("delivery: completing message: %w", err)
	}
	return c.Quit()
}

// dialContext dials the SMTP server, using the injected dialer when set (tests) or a
// context-aware net.Dialer otherwise.
func (m *SMTPMailer) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if m.dialFunc != nil {
		return m.dialFunc(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Compile-time checks that SMTPMailer satisfies the seams it is meant to fill.
var (
	_ identity.Mailer = (*SMTPMailer)(nil)
	_ Sender          = (*SMTPMailer)(nil)
)

// SendRecoveryEmailVerification implements identity.Mailer. The confirmation is delivered to
// recoveryEmail (the candidate recovery address), since opening it proves control of that channel.
// It reuses the address-verification template/link, which is semantically the same action (prove
// control of an address) applied to the recovery channel.
func (m *SMTPMailer) SendRecoveryEmailVerification(ctx context.Context, user *identity.User, recoveryEmail, token string) error {
	return m.deliver(ctx, EventEmailVerification, user, recoveryEmail, "", token)
}
