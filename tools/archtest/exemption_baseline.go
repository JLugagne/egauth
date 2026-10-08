package archtest

const coreBaseline = `
# Ratchet baseline of the non-legacy entries of exemption_lists.go: guard, symbol,
# ReliesOnAbsenceOf and RemovedBy, tab-separated. Lines may only be deleted, together with their
# entry. TestRatchetMatchesBaseline fails when this differs from the lists.
G02	github.com/JLugagne/egauth/passwords/...		WP7
G03	github.com/JLugagne/egauth/passwords/...		WP7
G04	github.com/JLugagne/egauth/event.Event.Err		WP5
G04	github.com/JLugagne/egauth/internal/examplekey/...		WP16
G04	github.com/JLugagne/egauth/internal/redirect.ErrNoOrigins		WP4
G04	github.com/JLugagne/egauth/passwords/...		WP7
G13	github.com/JLugagne/egauth.ActorFromContext		WP16
G13	github.com/JLugagne/egauth.ContextWithActor		WP16
G14	github.com/JLugagne/egauth/examples/fullstack/...		WP16
G14	errors.As		permanent
G14	net/http.Flusher		permanent
G14	net/http.Hijacker		permanent
`
