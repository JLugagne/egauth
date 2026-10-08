package event

// PublicAttrs returns the attributes of e that every sink may export: registered keys classified
// Public. PII, Secret and unregistered keys are dropped, so the result is safe to hand to any
// sink. It returns nil when nothing remains and never aliases e.Attrs.
func (e Event) PublicAttrs() map[string]any {
	return e.AttrsUpTo(Public)
}

// AttrsUpTo returns the registered attributes of e whose Sensitivity is at most limit, for a sink
// cleared to export more than Public (limit PII). Secret and unregistered keys are dropped even
// when limit is Secret, so no sink can obtain them through this method. It returns nil when
// nothing remains and never aliases e.Attrs.
func (e Event) AttrsUpTo(limit Sensitivity) map[string]any {
	if limit >= Secret {
		limit = PII
	}
	var out map[string]any
	for k, v := range e.Attrs {
		key := AttrKey(k)
		if !key.Registered() || key.Sensitivity() > limit {
			continue
		}
		if out == nil {
			out = make(map[string]any, len(e.Attrs))
		}
		out[k] = v
	}
	return out
}

// Public returns a copy of e whose Attrs are reduced to PublicAttrs. UserID and Err are kept: each
// exporting sink classifies them itself (see Event).
func (e Event) Public() Event {
	e.Attrs = e.PublicAttrs()
	return e
}
