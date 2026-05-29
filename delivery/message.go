package delivery

// Message is a rendered notification ready to be delivered over a channel (email or SMS). The
// Renderer produces it from a template and the per-event data; a Sender turns it into bytes on
// the wire.
//
// Subject and HTML are meaningful for email; an SMS Sender typically uses Text only and ignores
// the other fields.
type Message struct {
	// Subject is the message subject line. Email only.
	Subject string
	// Text is the plain-text body. It is required: every Message must have a text body so a
	// recipient (or an SMS channel) always has something to render.
	Text string
	// HTML is the optional HTML body. When non-empty the email Sender emits a
	// multipart/alternative message carrying both Text and HTML; when empty a plain-text email
	// is sent.
	HTML string
}

// hasHTML reports whether the message carries an HTML alternative body.
func (m Message) hasHTML() bool { return m.HTML != "" }
