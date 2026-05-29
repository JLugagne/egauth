package delivery

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSMTP is a minimal in-process SMTP server for tests. It speaks just enough of the protocol
// for net/smtp's client and captures the delivered messages and recipients.
type fakeSMTP struct {
	ln                net.Listener
	advertiseSTARTTLS bool

	mu       sync.Mutex
	messages [][]byte
	rcpts    []string
}

func newFakeSMTP(t *testing.T, advertiseSTARTTLS bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeSMTP{ln: ln, advertiseSTARTTLS: advertiseSTARTTLS}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeSMTP) host() string {
	host, _, _ := net.SplitHostPort(f.ln.Addr().String())
	return host
}

func (f *fakeSMTP) port() int {
	_, p, _ := net.SplitHostPort(f.ln.Addr().String())
	port := 0
	for _, c := range p {
		port = port*10 + int(c-'0')
	}
	return port
}

func (f *fakeSMTP) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeSMTP) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 fake ESMTP ready")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			_ = tp.PrintfLine("250-fake greets you")
			if f.advertiseSTARTTLS {
				_ = tp.PrintfLine("250-STARTTLS")
			}
			_ = tp.PrintfLine("250 8BITMIME")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			_ = tp.PrintfLine("250 OK")
		case strings.HasPrefix(cmd, "RCPT TO"):
			f.mu.Lock()
			f.rcpts = append(f.rcpts, line)
			f.mu.Unlock()
			_ = tp.PrintfLine("250 OK")
		case strings.HasPrefix(cmd, "DATA"):
			_ = tp.PrintfLine("354 End data with <CR><LF>.<CR><LF>")
			data, err := io.ReadAll(tp.DotReader())
			if err != nil {
				return
			}
			f.mu.Lock()
			f.messages = append(f.messages, data)
			f.mu.Unlock()
			_ = tp.PrintfLine("250 OK queued")
		case strings.HasPrefix(cmd, "QUIT"):
			_ = tp.PrintfLine("221 Bye")
			return
		default:
			_ = tp.PrintfLine("250 OK")
		}
	}
}

func (f *fakeSMTP) lastMessage(t *testing.T) []byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.messages, "expected at least one delivered message")
	return f.messages[len(f.messages)-1]
}

func (f *fakeSMTP) messageCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.messages)
}

func (f *fakeSMTP) lastRcpt(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.rcpts, "expected at least one RCPT TO")
	return f.rcpts[len(f.rcpts)-1]
}

// decodeMessage parses a received RFC 5322 message, returning its headers and decoded text/html
// bodies (decoding quoted-printable transfer encoding).
func decodeMessage(t *testing.T, raw []byte) (mail.Header, string, string) {
	t.Helper()
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	require.NoError(t, err)

	mediaType, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	require.NoError(t, err)

	if strings.HasPrefix(mediaType, "multipart/") {
		var text, html string
		mr := multipart.NewReader(m.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			body := decodeTransfer(t, p, p.Header.Get("Content-Transfer-Encoding"))
			if strings.HasPrefix(p.Header.Get("Content-Type"), "text/html") {
				html = body
			} else {
				text = body
			}
		}
		return m.Header, text, html
	}
	return m.Header, decodeTransfer(t, m.Body, m.Header.Get("Content-Transfer-Encoding")), ""
}

func decodeTransfer(t *testing.T, r io.Reader, encoding string) string {
	t.Helper()
	if strings.EqualFold(encoding, "quoted-printable") {
		r = quotedprintable.NewReader(r)
	}
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(b)
}

func newTestMailer(t *testing.T, f *fakeSMTP, opts ...Option) *SMTPMailer {
	t.Helper()
	base := []Option{WithLinks(LinkConfig{
		PasswordReset:     "https://app.example.com/reset",
		EmailVerification: "https://app.example.com/verify",
		MagicLink:         "https://app.example.com/signin",
		EmailChange:       "https://app.example.com/confirm",
	})}
	m, err := NewSMTPMailer(SMTPConfig{
		Host:     f.host(),
		Port:     f.port(),
		From:     "no-reply@example.com",
		FromName: "Example Security",
		TLS:      TLSNone,
	}, append(base, opts...)...)
	require.NoError(t, err)
	return m
}

func TestNewSMTPMailer_Validation(t *testing.T) {
	links := WithLinks(LinkConfig{PasswordReset: "https://app/reset"})

	t.Run("host required", func(t *testing.T) {
		_, err := NewSMTPMailer(SMTPConfig{From: "a@x.com"}, links)
		require.Error(t, err)
	})
	t.Run("from required", func(t *testing.T) {
		_, err := NewSMTPMailer(SMTPConfig{Host: "smtp"}, links)
		require.Error(t, err)
	})
	t.Run("from must be parseable", func(t *testing.T) {
		_, err := NewSMTPMailer(SMTPConfig{Host: "smtp", From: "not an email"}, links)
		require.Error(t, err)
	})
	t.Run("default templates require links", func(t *testing.T) {
		_, err := NewSMTPMailer(SMTPConfig{Host: "smtp", From: "a@x.com"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "WithLinks")
	})
	t.Run("all-empty LinkConfig is rejected for default templates", func(t *testing.T) {
		// WithLinks(LinkConfig{}) must not bypass the fail-fast guard: an empty config would
		// otherwise render every {{.Link}} as an empty string and ship broken emails.
		_, err := NewSMTPMailer(SMTPConfig{Host: "smtp", From: "a@x.com"}, WithLinks(LinkConfig{}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "WithLinks")
	})
	t.Run("custom renderer lifts the link requirement", func(t *testing.T) {
		r, err := NewTemplateRenderer()
		require.NoError(t, err)
		_, err = NewSMTPMailer(SMTPConfig{Host: "smtp", From: "a@x.com"}, WithRenderer(r))
		require.NoError(t, err)
	})
	t.Run("valid config", func(t *testing.T) {
		_, err := NewSMTPMailer(SMTPConfig{Host: "smtp", From: "a@x.com"}, links)
		require.NoError(t, err)
	})
}

func TestSMTPMailer_SendPasswordReset(t *testing.T) {
	f := newFakeSMTP(t, false)
	m := newTestMailer(t, f)

	user := testUser("user@example.com")
	require.NoError(t, m.SendPasswordReset(context.Background(), user, "secret-token"))

	hdr, text, html := decodeMessage(t, f.lastMessage(t))
	assert.Equal(t, `"Example Security" <no-reply@example.com>`, hdr.Get("From"))
	assert.Equal(t, "<user@example.com>", hdr.Get("To"))
	assert.Equal(t, "Reset your password", hdr.Get("Subject"))
	assert.NotEmpty(t, hdr.Get("Date"))
	assert.Empty(t, html)
	assert.Contains(t, text, "https://app.example.com/reset?token=secret-token")
	assert.Equal(t, "<user@example.com>", addrOf(t, f.lastRcpt(t)))
}

func TestSMTPMailer_SendEmailChange_DeliversToNewAddress(t *testing.T) {
	f := newFakeSMTP(t, false)
	m := newTestMailer(t, f)

	// The confirmation must go to the NEW address (proving control of it), not the current one.
	user := testUser("current@example.com")
	require.NoError(t, m.SendEmailChange(context.Background(), user, "new@example.com", "change-token"))

	hdr, text, _ := decodeMessage(t, f.lastMessage(t))
	assert.Equal(t, "<new@example.com>", hdr.Get("To"))
	assert.Equal(t, "<new@example.com>", addrOf(t, f.lastRcpt(t)))
	assert.Contains(t, text, "new@example.com")
	assert.Contains(t, text, "token=change-token")
	assert.Contains(t, text, "email=new%40example.com")
}

func TestSMTPMailer_Multipart(t *testing.T) {
	f := newFakeSMTP(t, false)
	r, err := NewTemplateRenderer(WithTemplate(
		EventMagicLink,
		"Sign in",
		"Open {{.Link}}",
		`<p>Open <a href="{{.Link}}">this link</a> for {{.User.Email}}</p>`,
	))
	require.NoError(t, err)
	m := newTestMailer(t, f, WithRenderer(r))

	require.NoError(t, m.SendMagicLink(context.Background(), testUser("user@example.com"), "tok"))

	hdr, text, html := decodeMessage(t, f.lastMessage(t))
	assert.True(t, strings.HasPrefix(hdr.Get("Content-Type"), "multipart/alternative"))
	assert.Contains(t, text, "https://app.example.com/signin?token=tok")
	assert.Contains(t, html, `href="https://app.example.com/signin?token=tok"`)
	assert.Contains(t, html, "user@example.com")
}

func TestSMTPMailer_STARTTLSUnsupportedFailsClosed(t *testing.T) {
	f := newFakeSMTP(t, false) // does NOT advertise STARTTLS
	m, err := NewSMTPMailer(SMTPConfig{
		Host: f.host(), Port: f.port(), From: "no-reply@example.com",
		TLS: TLSStartTLS,
	}, WithLinks(LinkConfig{PasswordReset: "https://app/reset"}))
	require.NoError(t, err)

	err = m.SendPasswordReset(context.Background(), testUser("u@example.com"), "tok")
	require.ErrorIs(t, err, ErrSTARTTLSUnsupported)
	assert.Zero(t, f.messageCount(), "no message must be sent over a cleartext link")
}

func TestSMTPMailer_ContextCancelled(t *testing.T) {
	f := newFakeSMTP(t, false)
	m := newTestMailer(t, f)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.SendPasswordReset(ctx, testUser("u@example.com"), "tok")
	require.Error(t, err)
}

func TestSMTPMailer_Send_GenericRecipient(t *testing.T) {
	f := newFakeSMTP(t, false)
	m := newTestMailer(t, f)

	require.NoError(t, m.Send(context.Background(), "ops@example.com", Message{Subject: "Hi", Text: "body"}))
	hdr, text, _ := decodeMessage(t, f.lastMessage(t))
	assert.Equal(t, "<ops@example.com>", hdr.Get("To"))
	assert.Equal(t, "Hi", hdr.Get("Subject"))
	assert.Equal(t, "body", strings.TrimRight(text, "\r\n"))
}

func TestSMTPMailer_InvalidRecipient(t *testing.T) {
	f := newFakeSMTP(t, false)
	m := newTestMailer(t, f)
	err := m.Send(context.Background(), "not an address", Message{Text: "x"})
	require.Error(t, err)
}

// addrOf extracts the bare address from an "RCPT TO:<addr>" line for comparison.
func addrOf(t *testing.T, rcptLine string) string {
	t.Helper()
	i := strings.IndexByte(rcptLine, '<')
	require.GreaterOrEqual(t, i, 0)
	return rcptLine[i:]
}
