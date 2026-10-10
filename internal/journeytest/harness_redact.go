package journeytest

import "log/slog"

const redacted = "REDACTED"

func (a MFAAccount) String() string {
	return "journeytest.MFAAccount{Email:" + a.Email + " Secret:" + redacted + " Recovery:" + redacted + "}"
}

func (a MFAAccount) GoString() string { return a.String() }

func (a MFAAccount) LogValue() slog.Value {
	return slog.GroupValue(slog.String("email", a.Email), slog.String("secret", redacted), slog.String("recovery", redacted))
}

func (c Credentials) String() string {
	return "journeytest.Credentials{Email:" + c.Email + " Password:" + redacted + "}"
}

func (c Credentials) GoString() string { return c.String() }

func (c Credentials) LogValue() slog.Value {
	return slog.GroupValue(slog.String("email", c.Email), slog.String("password", redacted))
}

func (t Text) String() string { return "journeytest.Text{Kind:" + t.Kind + " Code:" + redacted + "}" }

func (t Text) GoString() string { return t.String() }

func (t Text) LogValue() slog.Value {
	return slog.GroupValue(slog.String("kind", t.Kind), slog.String("code", redacted))
}

func (*World) String() string { return "journeytest.World{KEK:" + redacted + "}" }

func (w *World) GoString() string { return w.String() }

func (w *World) LogValue() slog.Value { return slog.StringValue(w.String()) }
