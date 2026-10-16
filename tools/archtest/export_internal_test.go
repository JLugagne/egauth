package archtest

func BindG06TypedEntryForTest(rel, name, row string) (restore func()) {
	saved := g06TypedEntries
	g06TypedEntries = append(append([]g06Typed(nil), saved...), g06Typed{rel: rel, name: name, row: row, removedBy: Permanent})
	return func() { g06TypedEntries = saved }
}
