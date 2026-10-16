package archtest

const coreBaseline = `
# Ratchet baseline of the non-legacy entries of exemption_lists.go: guard, symbol,
# ReliesOnAbsenceOf and RemovedBy, tab-separated. Lines may only be deleted, together with their
# entry. TestRatchetMatchesBaseline fails when this differs from the lists.
G14	errors.As		permanent
G14	net/http.Flusher		permanent
G14	net/http.Hijacker		permanent
`
